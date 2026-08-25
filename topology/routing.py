"""Conservative routed-topology correlation for WireScope.

This layer sits after the segment-aware topology builder. It does not perform
new network activity and it deliberately does not infer a physical hop from a
shared subnet alone. Its job is to turn persisted route/inventory evidence
into a clearer L3 graph:

    segment -> confirmed gateway/router -> segment

A multi-homed asset is only marked as a router candidate unless stronger
network-device/gateway evidence exists.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


def _roles(node: dict[str, Any]) -> list[str]:
    roles = [str(value) for value in (node.get("roles") or []) if value]
    node["roles"] = roles
    return roles


def _add_role(node: dict[str, Any], role: str) -> None:
    roles = _roles(node)
    if role not in roles:
        roles.append(role)


def _add_provenance(node: dict[str, Any], value: str) -> None:
    provenance = [str(item) for item in (node.get("provenance") or []) if item]
    if value not in provenance:
        provenance.append(value)
    node["provenance"] = provenance


def _segment_node(segment: dict[str, Any]) -> dict[str, Any]:
    segment_id = str(segment.get("id") or "")
    network = str(segment.get("network") or segment.get("label") or segment_id)
    return {
        "id": segment_id,
        "kind": "segment",
        "label": network,
        "network": network,
        "family": segment.get("family"),
        "roles": ["subnet"],
        "addresses": [],
        "names": [],
        "member_count": len(segment.get("members") or []),
        "segment_ids": [segment_id],
        "confidence": segment.get("confidence") or "inferred",
        "provenance": list(segment.get("provenance") or ["audit-scope"]),
    }


def _gateway_for_segment(
    topology: dict[str, Any],
    segment: dict[str, Any],
) -> dict[str, Any] | None:
    gateways = {str(value) for value in (segment.get("gateways") or []) if value}
    if not gateways:
        return None
    for node in topology.get("nodes") or []:
        addresses = {
            str(value).split("/", 1)[0]
            for value in (node.get("addresses") or [])
            if value
        }
        if addresses & gateways:
            return node
    return None


def _network_device_evidence(node: dict[str, Any]) -> bool:
    roles = set(_roles(node))
    return bool(
        node.get("kind") == "network-device"
        or roles.intersection(
            {
                "gateway",
                "network-device",
                "network-neighbor",
                "stp-root",
                "dhcp-server",
            }
        )
    )


def decorate_routed_topology(topology: dict[str, Any]) -> dict[str, Any]:
    """Decorate one audit topology with explicit L3 segment/router structure."""
    segments = [item for item in (topology.get("segments") or []) if item.get("id")]
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    node_by_id = {str(node.get("id")): node for node in nodes if node.get("id")}

    # Make every retained subnet a first-class L3 node. The UI may still draw
    # it as a visual region in general mode, but L3 now has an explicit object
    # to attach a gateway/router to.
    for segment in segments:
        segment_id = str(segment["id"])
        if segment_id not in node_by_id:
            node = _segment_node(segment)
            nodes.append(node)
            node_by_id[segment_id] = node

    confirmed_gateway_ids = {
        str(gateway.get("id"))
        for segment in segments
        for gateway in [_gateway_for_segment(topology, segment)]
        if gateway is not None and gateway.get("id")
    }

    # Remove the old appliance->gateway representation when the same evidence
    # can be expressed as segment->gateway. This is a semantic correction,
    # not merely a presentation change.
    rewritten: list[dict[str, Any]] = []
    seen_gateway_edges: set[tuple[str, str]] = set()
    for edge in edges:
        relation = str(edge.get("relation") or "")
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        provenance = set(str(value) for value in (edge.get("provenance") or []))

        if (
            relation == "default_gateway"
            and source.startswith("wirescope:")
            and target in confirmed_gateway_ids
            and "default-route" in provenance
        ):
            continue

        if relation != "segment_gateway":
            rewritten.append(edge)
            continue
        segment_id = str(edge.get("segment_id") or "")
        if not segment_id or segment_id not in node_by_id or not target:
            rewritten.append(edge)
            continue
        key = (segment_id, target)
        if key in seen_gateway_edges:
            continue
        seen_gateway_edges.add(key)
        updated = dict(edge)
        updated["source"] = segment_id
        updated["target"] = target
        updated["layer"] = "l3"
        updated["segment_ids"] = [segment_id]
        rewritten.append(updated)
    topology["edges"] = rewritten
    edges = rewritten

    # Ensure route evidence creates a segment->gateway edge even if an older
    # topology document did not already contain segment_gateway.
    for segment in segments:
        segment_id = str(segment["id"])
        gateway = _gateway_for_segment(topology, segment)
        if gateway is None:
            continue
        gateway_id = str(gateway.get("id") or "")
        if not gateway_id:
            continue
        _add_role(gateway, "gateway")
        _add_role(gateway, "router")
        _add_provenance(gateway, "confirmed-scope-route")
        connected = [str(value) for value in (gateway.get("connected_segments") or []) if value]
        if segment_id not in connected:
            connected.append(segment_id)
        gateway["connected_segments"] = sorted(set(connected))
        gateway["routing_confidence"] = "confirmed"

        if not any(
            edge.get("relation") == "segment_gateway"
            and edge.get("source") == segment_id
            and edge.get("target") == gateway_id
            for edge in edges
        ):
            edges.append(
                {
                    "id": f"edge:routed-gateway:{len(edges) + 1}",
                    "source": segment_id,
                    "target": gateway_id,
                    "relation": "segment_gateway",
                    "layer": "l3",
                    "confidence": "confirmed",
                    "provenance": ["confirmed-scope-route"],
                    "segment_id": segment_id,
                    "segment_ids": [segment_id],
                }
            )

    # Multi-segment inventory is useful evidence, but not proof that forwarding
    # is enabled. Keep the distinction explicit. Strong network-device
    # evidence upgrades the label to router; otherwise it remains a candidate.
    routers: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for node in nodes:
        if node.get("kind") in {"segment", "multicast-group", "wirescope"}:
            continue
        segment_ids = sorted(set(str(value) for value in (node.get("segment_ids") or []) if value))
        if len(segment_ids) < 2:
            if "router" in set(_roles(node)):
                routers.append(node)
            continue

        node["connected_segments"] = segment_ids
        _add_provenance(node, "multi-segment-addresses")
        if _network_device_evidence(node):
            _add_role(node, "router")
            node.setdefault("routing_confidence", "observed")
            routers.append(node)
        else:
            _add_role(node, "router-candidate")
            node["routing_confidence"] = "inferred"
            candidates.append(node)

    # A confirmed gateway is a router role even when only one audited segment
    # is currently visible. Deduplicate the metadata list by node id.
    router_by_id = {
        str(node.get("id")): node
        for node in [*routers, *nodes]
        if node.get("id") and "router" in set(node.get("roles") or [])
    }
    candidate_by_id = {
        str(node.get("id")): node
        for node in candidates
        if node.get("id") and str(node.get("id")) not in router_by_id
    }

    topology["routing"] = {
        "model": "segment-router-segment",
        "routers": [
            {
                "node_id": node_id,
                "label": node.get("label"),
                "connected_segments": list(node.get("connected_segments") or []),
                "confidence": node.get("routing_confidence") or "confirmed",
                "provenance": list(node.get("provenance") or []),
            }
            for node_id, node in sorted(router_by_id.items())
        ],
        "router_candidates": [
            {
                "node_id": node_id,
                "label": node.get("label"),
                "connected_segments": list(node.get("connected_segments") or []),
                "confidence": "inferred",
                "provenance": list(node.get("provenance") or []),
            }
            for node_id, node in sorted(candidate_by_id.items())
        ],
    }

    confidence = Counter(str(edge.get("confidence") or "unknown") for edge in edges)
    layers = Counter(str(edge.get("layer") or "general") for edge in edges)
    topology["summary"] = {
        **(topology.get("summary") or {}),
        "nodes": len(nodes),
        "edges": len(edges),
        "routers": len(router_by_id),
        "router_candidates": len(candidate_by_id),
        "confidence": dict(confidence),
        "layers": dict(layers),
    }
    topology["schema_version"] = max(3, int(topology.get("schema_version") or 1))
    topology["model"] = "routed-segment-aware"
    return topology


def decorate_global_routing_topology(topology: dict[str, Any]) -> dict[str, Any]:
    """Mark global gateway nodes that join multiple retained segments."""
    nodes = topology.get("nodes") or []
    edges = topology.get("edges") or []
    node_by_id = {str(node.get("id")): node for node in nodes if node.get("id")}
    attached: dict[str, set[str]] = {}
    for edge in edges:
        if edge.get("relation") != "segment_gateway":
            continue
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if source.startswith("segment:") and target:
            attached.setdefault(target, set()).add(source)

    routers = 0
    for node_id, segment_ids in attached.items():
        node = node_by_id.get(node_id)
        if node is None:
            continue
        node["connected_segments"] = sorted(segment_ids)
        _add_role(node, "gateway")
        if len(segment_ids) >= 2:
            _add_role(node, "router")
            node["routing_confidence"] = "confirmed"
            routers += 1

    topology["routing"] = {
        "model": "cross-audit-segment-router-segment",
        "routers": [
            {
                "node_id": node_id,
                "label": node_by_id[node_id].get("label"),
                "connected_segments": sorted(segment_ids),
                "confidence": "confirmed",
                "provenance": list(node_by_id[node_id].get("provenance") or []),
            }
            for node_id, segment_ids in sorted(attached.items())
            if len(segment_ids) >= 2 and node_id in node_by_id
        ],
    }
    topology["summary"] = {
        **(topology.get("summary") or {}),
        "routers": routers,
    }
    topology["schema_version"] = max(2, int(topology.get("schema_version") or 1))
    topology["model"] = "cross-audit-routed-segments"
    return topology
