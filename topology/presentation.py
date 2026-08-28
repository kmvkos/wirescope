"""Build UI-oriented projections without discarding canonical topology evidence.

The canonical ``nodes``/``edges`` remain untouched.  Presentation projections
answer a different question: what should an operator see in Structural, L2, L3
and Traffic views so that unrelated evidence classes do not become one noisy
hairball.
"""

from __future__ import annotations

import ipaddress
from typing import Any


MAX_STRUCTURAL_ENDPOINTS_PER_SEGMENT = 8


def _bare(value: Any) -> str:
    return str(value or "").split("/", 1)[0]


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(_bare(value))
    except ValueError:
        return None


def _network(value: Any) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(str(value or ""), strict=False)
    except ValueError:
        return None


def _node_in_network(
    node: dict[str, Any],
    network: ipaddress._BaseNetwork | None,
) -> bool:
    if network is None:
        return False
    for raw in node.get("addresses") or []:
        address = _ip(raw)
        if address is not None and address.version == network.version and address in network:
            return True
    return False


def _roles(node: dict[str, Any]) -> set[str]:
    return {str(value) for value in (node.get("roles") or []) if value}


def _is_link_local_only(node: dict[str, Any]) -> bool:
    addresses = [_ip(value) for value in (node.get("addresses") or [])]
    addresses = [value for value in addresses if value is not None]
    return bool(addresses) and all(value.is_link_local for value in addresses)


def _directed_broadcasts(topology: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for segment in topology.get("segments") or []:
        network = _network(segment.get("network"))
        if network is None:
            continue
        if network.version == 4 and network.prefixlen < 31:
            result.add(str(network.broadcast_address))
    return result


def _is_broadcast_node(node: dict[str, Any], broadcasts: set[str]) -> bool:
    if node.get("kind") == "multicast-group":
        return True
    for raw in node.get("addresses") or []:
        address = _ip(raw)
        if address is None:
            continue
        if address.is_multicast or str(address) in broadcasts or str(address) == "255.255.255.255":
            return True
    return False


def _primary_label(node: dict[str, Any]) -> str:
    names = [str(value).strip() for value in (node.get("names") or []) if str(value).strip()]
    for name in names:
        if not name.lower().startswith(("fe80:", "ff02:")):
            return name[:36]

    ipv4: list[str] = []
    global_or_ula_v6: list[str] = []
    link_local_v6: list[str] = []
    for raw in node.get("addresses") or []:
        address = _ip(raw)
        if address is None:
            continue
        if address.version == 4:
            ipv4.append(str(address))
        elif address.is_link_local:
            link_local_v6.append(str(address))
        else:
            global_or_ula_v6.append(str(address))
    if ipv4:
        return ipv4[0]

    label = str(node.get("label") or "").strip()
    if label and ":" not in label:
        return label[:36]
    if node.get("mac"):
        return str(node["mac"])
    if global_or_ula_v6:
        return global_or_ula_v6[0][:28]
    if link_local_v6:
        return f"IPv6 link-local · {link_local_v6[0][:18]}…"
    return label[:36] or str(node.get("id") or "узел")[:36]


def _importance(node: dict[str, Any], nontraffic_degree: dict[str, int]) -> int:
    roles = _roles(node)
    score = nontraffic_degree.get(str(node.get("id")), 0) * 30
    if node.get("kind") == "wirescope":
        score += 1000
    if roles.intersection({"gateway", "router", "network-device", "network-neighbor", "dhcp-server", "dns-server"}):
        score += 800
    if node.get("kind") == "network-device":
        score += 700
    if node.get("findings") or node.get("finding_count"):
        score += 300
    if node.get("services"):
        score += 150
    if node.get("state") == "responsive":
        score += 50
    return score


def _edge_subset(edges: list[dict[str, Any]], relations: set[str] | None = None, *, layer: str | None = None) -> list[str]:
    result: list[str] = []
    for edge in edges:
        if relations is not None and str(edge.get("relation") or "") not in relations:
            continue
        if layer is not None and str(edge.get("layer") or "general") != layer:
            continue
        if edge.get("id"):
            result.append(str(edge["id"]))
    return result


def _referenced_nodes(edges: list[dict[str, Any]], edge_ids: set[str]) -> set[str]:
    result: set[str] = set()
    for edge in edges:
        if str(edge.get("id") or "") not in edge_ids:
            continue
        if edge.get("source"):
            result.add(str(edge["source"]))
        if edge.get("target"):
            result.add(str(edge["target"]))
    return result


def decorate_presentation(topology: dict[str, Any]) -> dict[str, Any]:
    """Attach stable presentation projections and label/grouping hints."""

    nodes = list(topology.get("nodes") or [])
    edges = list(topology.get("edges") or [])
    node_by_id = {str(node.get("id")): node for node in nodes if node.get("id")}
    broadcasts = _directed_broadcasts(topology)

    communication_ids = {
        str(edge.get("id"))
        for edge in edges
        if edge.get("id") and str(edge.get("relation") or "") == "communication"
    }
    nontraffic_edges = [edge for edge in edges if str(edge.get("id") or "") not in communication_ids]
    nontraffic_degree: dict[str, int] = {}
    for edge in nontraffic_edges:
        for endpoint in (edge.get("source"), edge.get("target")):
            if endpoint:
                key = str(endpoint)
                nontraffic_degree[key] = nontraffic_degree.get(key, 0) + 1

    labels = {node_id: _primary_label(node) for node_id, node in node_by_id.items()}
    broadcast_ids = {
        node_id for node_id, node in node_by_id.items() if _is_broadcast_node(node, broadcasts)
    }
    link_local_only_ids = {
        node_id
        for node_id, node in node_by_id.items()
        if _is_link_local_only(node)
        and node.get("kind") == "endpoint"
        and nontraffic_degree.get(node_id, 0) == 0
    }

    infrastructure_ids: set[str] = set()
    for node_id, node in node_by_id.items():
        roles = _roles(node)
        if (
            node.get("kind") in {"wirescope", "network-device", "network-interface"}
            or roles.intersection({"gateway", "router", "network-device", "network-neighbor", "dhcp-server", "dns-server", "stp-root", "stp-bridge"})
        ):
            infrastructure_ids.add(node_id)

    structural_edge_ids = {
        str(edge.get("id"))
        for edge in nontraffic_edges
        if edge.get("id")
        and str(edge.get("source") or "") not in broadcast_ids
        and str(edge.get("target") or "") not in broadcast_ids
    }
    structural_referenced = _referenced_nodes(edges, structural_edge_ids)
    structural_ids = set(infrastructure_ids) | structural_referenced

    segment_groups: list[dict[str, Any]] = []
    for segment in topology.get("segments") or []:
        segment_id = str(segment.get("id") or "")
        segment_network = _network(segment.get("network"))
        declared_members = [
            str(value)
            for value in (segment.get("members") or [])
            if str(value) in node_by_id
            and str(value) not in broadcast_ids
            and str(value) not in link_local_only_ids
        ]
        declared_member_set = set(declared_members)

        # Some decorators run after the canonical segmented topology is built
        # (PCAP discovery/next-hop, SNMP, SSH).  Their nodes therefore cannot be
        # present in the original ``segment.members`` array.  Recover logical
        # segment membership conservatively from an explicit node address that
        # falls inside the segment CIDR; this is a logical grouping claim only,
        # never a physical-link or switch-port claim.
        address_derived_members = [
            node_id
            for node_id, node in node_by_id.items()
            if node_id not in declared_member_set
            and node_id not in broadcast_ids
            and node_id not in link_local_only_ids
            and _node_in_network(node, segment_network)
        ]
        address_derived_members.sort(key=lambda node_id: labels.get(node_id, node_id))
        members = declared_members + address_derived_members

        ordinary = [value for value in members if value not in infrastructure_ids]
        ordinary.sort(
            key=lambda node_id: (
                -_importance(node_by_id[node_id], nontraffic_degree),
                labels.get(node_id, node_id),
            )
        )
        visible = ordinary[:MAX_STRUCTURAL_ENDPOINTS_PER_SEGMENT]
        structural_ids.update(visible)
        segment_groups.append(
            {
                "segment_id": segment_id,
                "network": segment.get("network") or segment.get("label"),
                "member_count": len(members),
                "declared_member_count": len(declared_members),
                "address_derived_member_count": len(address_derived_members),
                "address_derived_member_ids": address_derived_members,
                "infrastructure_node_ids": [value for value in members if value in infrastructure_ids],
                "visible_endpoint_node_ids": visible,
                "collapsed_endpoint_node_ids": ordinary[MAX_STRUCTURAL_ENDPOINTS_PER_SEGMENT:],
                "collapsed_endpoint_count": max(0, len(ordinary) - len(visible)),
            }
        )

    # Keep the sensor visible even if a source produced no structural edge.
    structural_ids.update(
        node_id for node_id, node in node_by_id.items() if node.get("kind") == "wirescope"
    )
    structural_ids.difference_update(broadcast_ids)
    structural_ids.difference_update(link_local_only_ids)

    l2_edge_ids = set(_edge_subset(edges, layer="l2"))
    l3_edge_ids = set(_edge_subset(edges, layer="l3"))
    traffic_edge_ids = set(communication_ids)

    l2_node_ids = _referenced_nodes(edges, l2_edge_ids)
    l3_node_ids = _referenced_nodes(edges, l3_edge_ids)
    traffic_node_ids = _referenced_nodes(edges, traffic_edge_ids)
    l3_node_ids.update(
        node_id for node_id, node in node_by_id.items() if node.get("kind") == "wirescope"
    )

    # External PCAP endpoints stay in Traffic and never pollute the default
    # structural map solely because they communicated with an internal host.
    traffic_only_ids = {
        node_id
        for node_id in traffic_node_ids
        if nontraffic_degree.get(node_id, 0) == 0
        and node_id not in infrastructure_ids
        and node_by_id.get(node_id, {}).get("kind") != "asset"
    }
    structural_ids.difference_update(traffic_only_ids)

    topology["presentation"] = {
        "schema": "network-topology-presentation",
        "schema_version": 1,
        "default_view": "structural",
        "labels": labels,
        "views": {
            "structural": {
                "title": "Схема сети",
                "node_ids": sorted(structural_ids),
                "edge_ids": sorted(structural_edge_ids),
                "segment_groups": segment_groups,
                "description": "Инфраструктура, сегменты и доказанные структурные связи без PCAP hairball.",
            },
            "l2": {
                "title": "L2 / физика",
                "node_ids": sorted(l2_node_ids - broadcast_ids),
                "edge_ids": sorted(l2_edge_ids),
                "description": "LLDP/CDP/STP/FDB/switch-port/VLAN evidence; невидимые hops не дорисовываются.",
            },
            "l3": {
                "title": "L3 / маршрутизация",
                "node_ids": sorted(l3_node_ids - broadcast_ids),
                "edge_ids": sorted(l3_edge_ids),
                "description": "Подсети, gateways, routed interfaces и upstream evidence.",
            },
            "traffic": {
                "title": "Traffic / PCAP",
                "node_ids": sorted(traffic_node_ids - broadcast_ids),
                "edge_ids": sorted(traffic_edge_ids),
                "description": "Наблюдавшиеся communications из явно выбранного persisted PCAP.",
            },
            "evidence": {
                "title": "Все evidence",
                "node_ids": sorted(set(node_by_id) - broadcast_ids),
                "edge_ids": sorted(
                    str(edge.get("id")) for edge in edges if edge.get("id")
                ),
                "description": "Диагностический raw evidence graph; не является основной схемой сети.",
            },
        },
        "suppressed": {
            "broadcast_multicast_node_ids": sorted(broadcast_ids),
            "unidentified_link_local_node_ids": sorted(link_local_only_ids),
            "unidentified_link_local_count": len(link_local_only_ids),
            "traffic_only_node_ids": sorted(traffic_only_ids),
        },
    }
    return topology


__all__ = ["decorate_presentation"]
