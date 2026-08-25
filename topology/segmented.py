"""Segment-aware topology views layered on top of the persisted evidence model.

This module deliberately keeps physical/L2, routed/L3 and observed traffic
relationships separate.  It also fixes an important appliance property: a
host-wide default route is not automatically the gateway of the interface used
for an audit.  Only route evidence resolved for the selected audit/interface is
considered authoritative for a segment gateway.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
from typing import Any

from jobs.models import AuditStatus
from topology.builder import build_topology as build_legacy_topology


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _network(value: Any) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    text = str(value or "").split("/", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _route_rows(confirmed_scope: dict[str, Any] | None, interface: str) -> list[dict[str, Any]]:
    if not confirmed_scope:
        return []
    context = confirmed_scope.get("route_context") or {}
    rows = context.get("routes") if isinstance(context, dict) else None
    if not isinstance(rows, list):
        return []
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        route_interface = str(row.get("interface") or context.get("interface") or "")
        if interface and route_interface and route_interface != interface:
            continue
        result.append(row)
    return result


def _layer_for_relation(relation: str) -> str:
    if relation in {"layer2_neighbor", "stp_observed"}:
        return "l2"
    if relation in {"default_gateway", "segment_gateway", "dhcp_observed"}:
        return "l3"
    if relation == "communication":
        return "traffic"
    return "general"


def _node_addresses(node: dict[str, Any]) -> list[ipaddress._BaseAddress]:
    values = []
    for raw in node.get("addresses") or []:
        parsed = _ip(raw)
        if parsed is not None:
            values.append(parsed)
    return values


def _drop_invalid_host_default_route(
    topology: dict[str, Any],
    *,
    interface: str,
    confirmed_scope: dict[str, Any] | None,
) -> None:
    """Remove a host default route that was not resolved for this audit route context."""
    routes = _route_rows(confirmed_scope, interface)
    valid_gateways = {
        str(address)
        for row in routes
        for address in [_ip(row.get("gateway"))]
        if address is not None
    }
    nodes = {str(node.get("id")): node for node in topology.get("nodes") or []}
    kept_edges = []
    for edge in topology.get("edges") or []:
        provenance = set(edge.get("provenance") or [])
        if edge.get("relation") == "default_gateway" and "default-route" in provenance:
            other_id = edge.get("target") if str(edge.get("source", "")).startswith("wirescope:") else edge.get("source")
            other = nodes.get(str(other_id)) or {}
            addresses = {str(item) for item in _node_addresses(other)}
            if not (addresses & valid_gateways):
                continue
        kept_edges.append(edge)
    topology["edges"] = kept_edges

    referenced = {str(edge.get("source")) for edge in kept_edges} | {str(edge.get("target")) for edge in kept_edges}
    topology["nodes"] = [
        node
        for node in topology.get("nodes") or []
        if not (
            node.get("kind") == "endpoint"
            and set(node.get("provenance") or []) == {"default-route"}
            and str(node.get("id")) not in referenced
        )
    ]


def _decorate_segments(
    topology: dict[str, Any],
    *,
    confirmed_scope: dict[str, Any] | None,
) -> None:
    interface = str((topology.get("audit") or {}).get("interface") or "")
    routes = _route_rows(confirmed_scope, interface)
    route_by_target = {str(row.get("target")): row for row in routes if row.get("target")}

    targets = []
    if confirmed_scope:
        targets.extend(confirmed_scope.get("targets") or [])
    if not targets:
        scope = (topology.get("audit") or {}).get("scope") or {}
        if isinstance(scope, dict):
            targets.extend(scope.get("targets") or scope.get("observed") or [])

    networks: list[ipaddress._BaseNetwork] = []
    for target in targets:
        network = _network(target)
        if network is not None and network not in networks:
            networks.append(network)

    nodes = {str(node.get("id")): node for node in topology.get("nodes") or []}
    appliance_id = f"wirescope:{interface or 'unknown'}"
    segments: list[dict[str, Any]] = []

    for network in networks:
        segment_id = f"segment:{network}"
        members: list[str] = []
        for node_id, node in nodes.items():
            if any(address.version == network.version and address in network for address in _node_addresses(node)):
                members.append(node_id)
                current = list(node.get("segment_ids") or [])
                if segment_id not in current:
                    current.append(segment_id)
                node["segment_ids"] = current

        route = route_by_target.get(str(network))
        if route is None:
            # ResolvedScope keeps the canonical target string. Fall back to
            # network membership of the route representative address for
            # single-host targets and equivalent canonical representations.
            for candidate in routes:
                representative = _ip(candidate.get("representative_address"))
                if representative is not None and representative.version == network.version and representative in network:
                    route = candidate
                    break

        gateways: list[str] = []
        if route:
            gateway = _ip(route.get("gateway"))
            if gateway is not None:
                gateway_text = str(gateway)
                gateways.append(gateway_text)
                gateway_node = next(
                    (
                        node
                        for node in nodes.values()
                        if gateway in _node_addresses(node)
                    ),
                    None,
                )
                if gateway_node is None:
                    gateway_node = {
                        "id": f"endpoint:{gateway_text}",
                        "kind": "endpoint",
                        "label": gateway_text,
                        "roles": ["gateway"],
                        "addresses": [gateway_text],
                        "names": [],
                        "provenance": ["confirmed-scope-route"],
                        "confidence": "confirmed",
                        "segment_ids": [segment_id],
                    }
                    topology.setdefault("nodes", []).append(gateway_node)
                    nodes[gateway_node["id"]] = gateway_node
                else:
                    roles = list(gateway_node.get("roles") or [])
                    if "gateway" not in roles:
                        roles.append("gateway")
                    gateway_node["roles"] = roles
                    segment_ids = list(gateway_node.get("segment_ids") or [])
                    if segment_id not in segment_ids:
                        segment_ids.append(segment_id)
                    gateway_node["segment_ids"] = segment_ids

                if not any(
                    edge.get("relation") == "segment_gateway"
                    and edge.get("source") == appliance_id
                    and edge.get("target") == gateway_node["id"]
                    and edge.get("segment_id") == segment_id
                    for edge in topology.get("edges") or []
                ):
                    topology.setdefault("edges", []).append(
                        {
                            "id": f"edge:segment-gateway:{len(topology.get('edges') or []) + 1}",
                            "source": appliance_id,
                            "target": gateway_node["id"],
                            "relation": "segment_gateway",
                            "confidence": "confirmed",
                            "provenance": ["confirmed-scope-route"],
                            "segment_id": segment_id,
                            "layer": "l3",
                        }
                    )

        segments.append(
            {
                "id": segment_id,
                "kind": "subnet" if network.prefixlen < network.max_prefixlen else "host-scope",
                "label": str(network),
                "network": str(network),
                "family": network.version,
                "prefix_length": network.prefixlen,
                "members": sorted(set(members)),
                "gateways": gateways,
                "interface": str((route or {}).get("interface") or interface or ""),
                "source_address": (route or {}).get("source_address"),
                "directly_connected": bool((route or {}).get("directly_connected")) if route else None,
                "confidence": "confirmed" if confirmed_scope else "inferred",
                "provenance": ["confirmed-scope-route"] if route else ["audit-scope"],
            }
        )

    for edge in topology.get("edges") or []:
        edge.setdefault("layer", _layer_for_relation(str(edge.get("relation") or "")))
        segment_ids = []
        if edge.get("segment_id"):
            segment_ids.append(edge["segment_id"])
        for endpoint in (edge.get("source"), edge.get("target")):
            node = nodes.get(str(endpoint))
            if node:
                for segment_id in node.get("segment_ids") or []:
                    if segment_id not in segment_ids:
                        segment_ids.append(segment_id)
        edge["segment_ids"] = segment_ids

    topology["segments"] = segments
    topology["layers"] = {
        "general": {"label": "Общая", "description": "Сегменты, шлюзы и основные доказанные связи."},
        "l2": {"label": "L2", "description": "MAC/VLAN/LLDP/CDP/STP и канальный контекст."},
        "l3": {"label": "L3", "description": "IP-подсети, маршруты, шлюзы и DHCP-router observations."},
        "traffic": {"label": "Traffic", "description": "Наблюдавшиеся в PCAP связи, протоколы и порты."},
    }

    edge_rows = topology.get("edges") or []
    topology["summary"] = {
        **(topology.get("summary") or {}),
        "nodes": len(topology.get("nodes") or []),
        "edges": len(edge_rows),
        "segments": len(segments),
        "confidence": dict(Counter(str(edge.get("confidence") or "unknown") for edge in edge_rows)),
        "layers": dict(Counter(str(edge.get("layer") or "general") for edge in edge_rows)),
    }


def build_topology(
    services,
    audit_id: str,
    *,
    traffic_analysis_job_id: str | None = None,
) -> dict[str, Any]:
    topology = build_legacy_topology(
        services,
        audit_id,
        traffic_analysis_job_id=traffic_analysis_job_id,
    )
    latest_scope = services.inventory.latest_scope(audit_id)
    confirmed_scope = latest_scope.model_dump(mode="json") if latest_scope else None
    interface = str((topology.get("audit") or {}).get("interface") or "")
    _drop_invalid_host_default_route(
        topology,
        interface=interface,
        confirmed_scope=confirmed_scope,
    )
    _decorate_segments(topology, confirmed_scope=confirmed_scope)
    topology["schema_version"] = 2
    topology["model"] = "segment-aware"
    return topology


def build_global_topology(services, *, limit: int = 100) -> dict[str, Any]:
    """Build a conservative cross-audit overview of all retained scanned segments.

    The global view intentionally aggregates *segments and confirmed gateways*,
    not every historical asset into one identity graph.  Cross-audit asset
    identity needs its own conflict-aware history model and is therefore not
    guessed here.
    """
    page = services.jobs.list_audits(limit=max(1, min(limit, 100)), offset=0)
    segment_nodes: dict[str, dict[str, Any]] = {}
    gateway_nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    audit_refs: list[dict[str, Any]] = []

    for audit in page.items:
        if audit.status not in {
            AuditStatus.COMPLETED,
            AuditStatus.FAILED,
            AuditStatus.CANCELLED,
            AuditStatus.INTERRUPTED,
        }:
            continue
        try:
            topology = build_topology(services, audit.id)
        except Exception:
            continue
        if not topology.get("segments"):
            continue
        audit_refs.append(
            {
                "id": audit.id,
                "profile": audit.profile,
                "interface": audit.interface,
                "status": audit.status.value,
                "created_at": audit.created_at.isoformat(),
            }
        )
        nodes = {str(node.get("id")): node for node in topology.get("nodes") or []}
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
            aggregate["member_count"] = max(aggregate["member_count"], len(segment.get("members") or []))
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
                # Preserve a known inventory label if this audit identified the gateway.
                for node in nodes.values():
                    if gateway_text in [str(value).split("/", 1)[0] for value in node.get("addresses") or []]:
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
    return {
        "schema": "network-topology-global",
        "schema_version": 1,
        "generated_at": _utc_now(),
        "model": "cross-audit-segments",
        "summary": {
            "segments": len(segment_nodes),
            "gateways": len(gateway_nodes),
            "edges": len(edge_rows),
            "audits": len(audit_refs),
        },
        "nodes": nodes,
        "edges": edge_rows,
        "segments": list(segment_nodes.values()),
        "audits": audit_refs,
        "layers": {
            "general": {"label": "Общая"},
            "l3": {"label": "L3"},
        },
        "warnings": [
            "Глобальная карта объединяет сохранённые подсети и подтверждённые route/gateway evidence. Она не склеивает устройства разных аудитов по одному hostname или предположению."
        ],
    }
