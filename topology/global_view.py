"""Fail-visible cross-audit topology aggregation.

The global topology view is intentionally conservative: it aggregates retained
segments and confirmed gateway evidence, but does not guess cross-audit asset
identity.  Unlike the legacy aggregator, failures in one retained audit are
reported explicitly instead of being silently omitted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from jobs.models import AuditStatus
from topology.segmented import build_topology


_TERMINAL_AUDIT_STATUSES = {
    AuditStatus.COMPLETED,
    AuditStatus.FAILED,
    AuditStatus.CANCELLED,
    AuditStatus.INTERRUPTED,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _audit_ref(audit) -> dict[str, Any]:
    return {
        "id": audit.id,
        "profile": audit.profile,
        "interface": audit.interface,
        "status": audit.status.value,
        "created_at": audit.created_at.isoformat(),
    }


def _source_error(audit, exc: Exception) -> dict[str, Any]:
    return {
        "audit_id": audit.id,
        "profile": audit.profile,
        "interface": audit.interface,
        "status": audit.status.value,
        "component": "topology",
        "code": "source_unavailable",
        "error_type": type(exc).__name__,
    }


def build_global_topology(services, *, limit: int = 100) -> dict[str, Any]:
    """Build a conservative global view and make incomplete sources explicit."""
    page = services.jobs.list_audits(limit=max(1, min(limit, 100)), offset=0)
    segment_nodes: dict[str, dict[str, Any]] = {}
    gateway_nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    audit_refs: list[dict[str, Any]] = []
    source_errors: list[dict[str, Any]] = []
    considered = 0

    for audit in page.items:
        if audit.status not in _TERMINAL_AUDIT_STATUSES:
            continue
        considered += 1
        try:
            topology = build_topology(services, audit.id)
        except Exception as exc:
            source_errors.append(_source_error(audit, exc))
            continue
        if not topology.get("segments"):
            continue

        audit_refs.append(_audit_ref(audit))
        nodes = {
            str(node.get("id")): node
            for node in topology.get("nodes") or []
        }
        for segment in topology.get("segments") or []:
            network = str(segment.get("network") or segment.get("label") or "")
            if not network:
                continue
            node_id = f"segment:{network}"
            aggregate = segment_nodes.setdefault(
                node_id,
                {
                    "id": node_id,
                    "kind": "segment",
                    "label": network,
                    "network": network,
                    "family": segment.get("family"),
                    "roles": ["subnet"],
                    "audit_ids": [],
                    "interfaces": [],
                    "member_count": 0,
                    "scan_count": 0,
                    "confidence": "confirmed",
                    "provenance": ["retained-audits"],
                },
            )
            if audit.id not in aggregate["audit_ids"]:
                aggregate["audit_ids"].append(audit.id)
            if audit.interface and audit.interface not in aggregate["interfaces"]:
                aggregate["interfaces"].append(audit.interface)
            aggregate["member_count"] = max(
                aggregate["member_count"],
                len(segment.get("members") or []),
            )
            aggregate["scan_count"] += 1

            for gateway in segment.get("gateways") or []:
                gateway_text = str(gateway)
                gateway_id = f"gateway:{gateway_text}"
                gateway_node = gateway_nodes.setdefault(
                    gateway_id,
                    {
                        "id": gateway_id,
                        "kind": "endpoint",
                        "label": gateway_text,
                        "addresses": [gateway_text],
                        "roles": ["gateway"],
                        "confidence": "confirmed",
                        "provenance": ["confirmed-scope-route"],
                    },
                )
                for node in nodes.values():
                    addresses = [
                        str(value).split("/", 1)[0]
                        for value in node.get("addresses") or []
                    ]
                    if gateway_text in addresses:
                        if node.get("label") and node.get("label") != gateway_text:
                            gateway_node["label"] = node.get("label")
                        break

                edge_key = (node_id, gateway_id)
                edge = edges.setdefault(
                    edge_key,
                    {
                        "id": f"global-edge:{len(edges) + 1}",
                        "source": node_id,
                        "target": gateway_id,
                        "relation": "segment_gateway",
                        "layer": "l3",
                        "confidence": "confirmed",
                        "provenance": ["confirmed-scope-route"],
                        "audit_ids": [],
                    },
                )
                if audit.id not in edge["audit_ids"]:
                    edge["audit_ids"].append(audit.id)

    nodes = [*segment_nodes.values(), *gateway_nodes.values()]
    edge_rows = list(edges.values())
    partial = bool(source_errors)
    warnings = [
        "Глобальная карта объединяет сохранённые подсети и подтверждённые route/gateway evidence. Она не склеивает устройства разных аудитов по одному hostname или предположению."
    ]
    if partial:
        warnings.append(
            f"Глобальная карта неполная: не удалось построить topology для {len(source_errors)} сохранённых аудитов. Подробности доступны в source_errors."
        )

    return {
        "schema": "network-topology-global",
        "schema_version": 2,
        "generated_at": _utc_now(),
        "model": "cross-audit-segments",
        "partial": partial,
        "source_errors": source_errors,
        "summary": {
            "segments": len(segment_nodes),
            "gateways": len(gateway_nodes),
            "edges": len(edge_rows),
            "audits": len(audit_refs),
            "audits_considered": considered,
            "source_errors": len(source_errors),
        },
        "nodes": nodes,
        "edges": edge_rows,
        "segments": list(segment_nodes.values()),
        "audits": audit_refs,
        "layers": {
            "general": {"label": "Общая"},
            "l3": {"label": "L3"},
        },
        "warnings": warnings,
    }
