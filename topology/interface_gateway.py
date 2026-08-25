"""Interface-specific gateway enrichment from persisted local configuration.

This decorator fixes a common multi-homed appliance case without weakening the
route safety contract.  The kernel-preferred host default route may belong to a
NAT/management NIC while the audited LAN interface has its own default route or
DHCP router option.  Only evidence explicitly tied to the audit interface is
accepted.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from reports.sources import load_report_source


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value or "").split("/", 1)[0])
    except ValueError:
        return None


def _unique(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _node_for_address(topology: dict[str, Any], address: str) -> dict[str, Any] | None:
    wanted = _ip(address)
    if wanted is None:
        return None
    for node in topology.get("nodes") or []:
        for raw in node.get("addresses") or []:
            if _ip(raw) == wanted:
                return node
    return None


def _segment_for_address(topology: dict[str, Any], address: str) -> dict[str, Any] | None:
    wanted = _ip(address)
    if wanted is None:
        return None
    for segment in topology.get("segments") or []:
        try:
            network = ipaddress.ip_network(str(segment.get("network") or ""), strict=False)
        except ValueError:
            continue
        if wanted.version == network.version and wanted in network:
            return segment
    return None


def _candidate_gateways(environment: dict[str, Any], interface: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []

    for route in environment.get("default_routes") or []:
        if not isinstance(route, dict) or str(route.get("interface") or "") != interface:
            continue
        gateway = _ip(route.get("gateway"))
        if gateway is None:
            continue
        candidates.append(
            {
                "address": str(gateway),
                "provenance": "interface-default-route",
                "source": "local route table",
            }
        )

    # Backward-compatible environment snapshots may only have one default_route.
    legacy = environment.get("default_route")
    if isinstance(legacy, dict) and str(legacy.get("interface") or "") == interface:
        gateway = _ip(legacy.get("gateway"))
        if gateway is not None:
            candidates.append(
                {
                    "address": str(gateway),
                    "provenance": "interface-default-route",
                    "source": "local route table",
                }
            )

    for lease in environment.get("dhcp_leases") or []:
        if not isinstance(lease, dict) or str(lease.get("interface") or "") != interface:
            continue
        for raw in lease.get("routers") or []:
            gateway = _ip(raw)
            if gateway is None:
                continue
            candidates.append(
                {
                    "address": str(gateway),
                    "provenance": "dhcp-lease-router",
                    "source": str(lease.get("source") or "local DHCP lease"),
                }
            )

    deduplicated: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item["address"], item["provenance"])
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    return deduplicated


def decorate_interface_gateway(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    """Add gateway evidence bound to the selected audit interface only."""
    audit = services.jobs.get_audit(audit_id)
    report_source = load_report_source(
        audit=audit,
        database=services.database,
        inventory=services.inventory,
        findings=services.findings,
        evidence_store=services.evidence,
    )
    environment = report_source.environment or {}
    interface = str((topology.get("audit") or {}).get("interface") or audit.interface or "")
    if not interface:
        return topology

    sensor_id = f"wirescope:{interface}"
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])

    for candidate in _candidate_gateways(environment, interface):
        address = candidate["address"]
        provenance = candidate["provenance"]
        gateway = _node_for_address(topology, address)
        segment = _segment_for_address(topology, address)
        segment_id = str((segment or {}).get("id") or "") or None

        if gateway is None:
            gateway = {
                "id": f"endpoint:{address}",
                "kind": "endpoint",
                "label": address,
                "roles": ["gateway"],
                "addresses": [address],
                "names": [],
                "provenance": [provenance],
                "confidence": "confirmed",
                "segment_ids": [segment_id] if segment_id else [],
            }
            nodes.append(gateway)
        else:
            gateway["roles"] = _unique([*(gateway.get("roles") or []), "gateway"])
            gateway["provenance"] = _unique([*(gateway.get("provenance") or []), provenance])
            if gateway.get("confidence") != "confirmed":
                gateway["confidence"] = "confirmed"
            if segment_id:
                gateway["segment_ids"] = _unique([*(gateway.get("segment_ids") or []), segment_id])

        if segment is not None:
            segment["gateways"] = _unique([*(segment.get("gateways") or []), address])

        if any(
            str(edge.get("source") or "") == sensor_id
            and str(edge.get("target") or "") == str(gateway.get("id") or "")
            and str(edge.get("relation") or "") in {"segment_gateway", "default_gateway"}
            and provenance in set(edge.get("provenance") or [])
            for edge in edges
        ):
            continue

        edge = {
            "id": f"edge:interface-gateway:{len(edges) + 1}",
            "source": sensor_id,
            "target": gateway["id"],
            "relation": "segment_gateway",
            "layer": "l3",
            "confidence": "confirmed",
            "provenance": [provenance],
            "gateway_source": candidate["source"],
            "segment_ids": [segment_id] if segment_id else [],
        }
        if segment_id:
            edge["segment_id"] = segment_id
        edges.append(edge)

    return topology


__all__ = ["decorate_interface_gateway"]
