"""Attach persisted audit findings to topology asset nodes.

This decorator performs no network activity. It only projects findings that
already belong to the audit onto nodes with a matching durable inventory
``asset_id``. Topology-only endpoints discovered through PCAP/SNMP are not
silently promoted to inventory assets merely to carry findings.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


_PAGE_SIZE = 500
_MAX_FINDINGS = 5000
_MAX_FINDINGS_PER_NODE = 32


def decorate_findings(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    rows = []
    offset = 0
    total = 0
    while offset < _MAX_FINDINGS:
        page = services.findings.list_findings(
            audit_id=audit_id,
            limit=min(_PAGE_SIZE, _MAX_FINDINGS - offset),
            offset=offset,
        )
        total = page.total
        rows.extend(page.items)
        offset += len(page.items)
        if not page.items or offset >= page.total:
            break

    attach_findings(topology, rows, total=total)
    if total > len(rows):
        topology.setdefault("warnings", []).append(
            f"Topology finding projection was bounded to {_MAX_FINDINGS} of {total} findings."
        )
    return topology


def attach_findings(
    topology: dict[str, Any],
    findings: Iterable[Any],
    *,
    total: int | None = None,
) -> dict[str, Any]:
    by_asset: dict[str, list[dict[str, Any]]] = {}
    severity = Counter()
    status = Counter()
    projected = 0

    for finding in findings:
        asset_id = _value(finding, "asset_id")
        if not asset_id:
            continue
        row = {
            "id": _value(finding, "id"),
            "rule_id": _value(finding, "rule_id"),
            "title": _value(finding, "title"),
            "severity": _enum_value(_value(finding, "severity")),
            "confidence": _enum_value(_value(finding, "confidence")),
            "status": _enum_value(_value(finding, "status")),
            "service_id": _value(finding, "service_id"),
            "description": _value(finding, "description"),
            "recommendation": _value(finding, "recommendation"),
        }
        by_asset.setdefault(str(asset_id), []).append(row)
        severity[row["severity"] or "unknown"] += 1
        status[row["status"] or "unknown"] += 1
        projected += 1

    nodes_with_findings = 0
    truncated_nodes = 0
    for node in topology.get("nodes") or []:
        asset_id = str(node.get("asset_id") or "")
        if not asset_id:
            continue
        rows = by_asset.get(asset_id, [])
        node["finding_count"] = len(rows)
        node["findings"] = rows[:_MAX_FINDINGS_PER_NODE]
        node["findings_truncated"] = len(rows) > _MAX_FINDINGS_PER_NODE
        if rows:
            nodes_with_findings += 1
        if node["findings_truncated"]:
            truncated_nodes += 1

    topology["finding_summary"] = {
        "total": int(total if total is not None else projected),
        "projected_to_assets": projected,
        "nodes_with_findings": nodes_with_findings,
        "truncated_nodes": truncated_nodes,
        "severity": dict(severity),
        "status": dict(status),
        "max_findings_per_node": _MAX_FINDINGS_PER_NODE,
    }
    return topology


def _value(item: Any, key: str) -> Any:
    if isinstance(item, dict):
        return item.get(key)
    return getattr(item, key, None)


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    raw = getattr(value, "value", value)
    text = str(raw).strip()
    return text or None


__all__ = ["attach_findings", "decorate_findings"]
