"""Deterministic comparison of two persisted WireScope topology views.

Cross-audit identity is deliberately conservative.  A MAC address or IP address
may correlate a node; a hostname alone does not.  Nodes without a defensible
stable identity remain side-local so the comparison never invents continuity.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any


_DIRECTED_RELATIONS = {
    "communication",
    "default_gateway",
    "route_hop",
    "route_target",
    "segment_gateway",
}
_IGNORED_NODE_KINDS = {"multicast-group", "route-gap"}
_NODE_FIELDS = (
    "kind",
    "label",
    "roles",
    "addresses",
    "names",
    "vlan_ids",
    "segment_ids",
    "connected_segments",
)
_EDGE_FIELDS = (
    "confidence",
    "provenance",
    "segment_ids",
    "vlan_ids",
    "port_name",
    "port_id",
    "local_port",
    "remote_port",
    "ttl",
)
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normal_mac(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("-", ":")
    if not _MAC_RE.fullmatch(text):
        return None
    if text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return None
    return text


def _normal_ip(value: Any) -> str | None:
    text = str(value or "").strip().split("/", 1)[0]
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_multicast or address.is_unspecified:
        return None
    return str(address)


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _stable_node_key(node: dict[str, Any], *, side: str) -> tuple[str | None, str]:
    kind = str(node.get("kind") or "endpoint")
    if kind in _IGNORED_NODE_KINDS:
        return None, "ignored"

    network = str(node.get("network") or "").strip()
    node_id = str(node.get("id") or "")
    if kind == "segment" or node_id.startswith("segment:"):
        candidate = network or node_id.removeprefix("segment:")
        try:
            return f"segment:{ipaddress.ip_network(candidate, strict=False)}", "network"
        except ValueError:
            return f"segment:{candidate}", "network"

    mac = _normal_mac(node.get("mac"))
    if mac:
        return f"mac:{mac}", "mac"

    for field in ("remote_chassis_id", "chassis_id", "lldp_chassis_id"):
        chassis = _normal_mac(node.get(field))
        if chassis:
            return f"chassis:{chassis}", "chassis"

    addresses = sorted(
        {value for raw in node.get("addresses") or [] if (value := _normal_ip(raw))},
        key=_ip_sort_key,
    )
    if addresses:
        return f"ip:{addresses[0]}", "ip"

    for prefix in ("endpoint:", "gateway:", "route-hop:", "snmp-device:", "snmp-arp:"):
        if node_id.startswith(prefix):
            suffix = _normal_ip(node_id[len(prefix):])
            if suffix:
                return f"ip:{suffix}", "ip"

    if kind == "wirescope" and node_id.startswith("wirescope:"):
        return node_id, "interface"

    # Never correlate two otherwise anonymous nodes merely because their label
    # or hostname happens to match in separate audits.
    return f"opaque:{side}:{node_id or id(node)}", "opaque"


def _normal_value(value: Any) -> Any:
    if isinstance(value, list):
        normalized = [_normal_value(item) for item in value]
        return sorted(normalized, key=lambda item: repr(item))
    if isinstance(value, tuple):
        return _normal_value(list(value))
    if isinstance(value, dict):
        return {key: _normal_value(value[key]) for key in sorted(value)}
    return value


def _project(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        field: _normal_value(source.get(field))
        for field in fields
        if source.get(field) not in (None, [], {}, "")
    }


def _node_descriptor(key: str, node: dict[str, Any], basis: str) -> dict[str, Any]:
    return {
        "key": key,
        "match_basis": basis,
        "kind": node.get("kind"),
        "label": node.get("label") or key,
        "addresses": sorted(
            {value for raw in node.get("addresses") or [] if (value := _normal_ip(raw))},
            key=_ip_sort_key,
        ),
        "mac": _normal_mac(node.get("mac")),
        "roles": sorted({str(value) for value in node.get("roles") or []}),
        "vlan_ids": sorted({int(value) for value in node.get("vlan_ids") or [] if str(value).isdigit()}),
    }


def _edge_descriptor(key: str, edge: dict[str, Any], node_keys: dict[str, str]) -> dict[str, Any]:
    return {
        "key": key,
        "relation": edge.get("relation"),
        "mapping_type": edge.get("mapping_type"),
        "source": node_keys.get(str(edge.get("source"))),
        "target": node_keys.get(str(edge.get("target"))),
        "confidence": edge.get("confidence"),
        "port_name": edge.get("port_name"),
        "vlan_ids": sorted({int(value) for value in edge.get("vlan_ids") or [] if str(value).isdigit()}),
    }


def _changed_fields(before: dict[str, Any], after: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    left = _project(before, fields)
    right = _project(after, fields)
    changes = {}
    for field in sorted(set(left) | set(right)):
        if left.get(field) != right.get(field):
            changes[field] = {"before": left.get(field), "after": right.get(field)}
    return changes


def _snapshot(topology: dict[str, Any], *, side: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    basis: dict[str, str] = {}
    id_to_key: dict[str, str] = {}
    ignored_nodes = 0
    duplicate_keys = 0

    for node in topology.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        key, match_basis = _stable_node_key(node, side=side)
        if key is None:
            ignored_nodes += 1
            continue
        node_id = str(node.get("id") or "")
        final_key = key
        if final_key in nodes:
            duplicate_keys += 1
            final_key = f"{key}#duplicate:{side}:{node_id or duplicate_keys}"
            match_basis = "duplicate"
        nodes[final_key] = node
        basis[final_key] = match_basis
        if node_id:
            id_to_key[node_id] = final_key

    edges: dict[str, dict[str, Any]] = {}
    ignored_edges = 0
    for edge in topology.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        source = id_to_key.get(str(edge.get("source") or ""))
        target = id_to_key.get(str(edge.get("target") or ""))
        if not source or not target:
            ignored_edges += 1
            continue
        relation = str(edge.get("relation") or "unknown")
        mapping = str(edge.get("mapping_type") or "")
        if relation not in _DIRECTED_RELATIONS:
            source, target = sorted((source, target))
        key = f"{relation}|{mapping}|{source}|{target}"
        if key in edges:
            # Parallel evidence with identical structural endpoints is compared
            # as one logical relation; merge list-like evidence conservatively.
            merged = dict(edges[key])
            for field in ("provenance", "segment_ids", "vlan_ids"):
                values = list(merged.get(field) or [])
                for value in edge.get(field) or []:
                    if value not in values:
                        values.append(value)
                if values:
                    merged[field] = values
            edges[key] = merged
        else:
            edges[key] = edge

    segments = sorted(
        {
            str(item.get("network") or item.get("label") or "")
            for item in topology.get("segments") or []
            if isinstance(item, dict) and (item.get("network") or item.get("label"))
        }
    )
    return {
        "nodes": nodes,
        "basis": basis,
        "id_to_key": id_to_key,
        "edges": edges,
        "segments": segments,
        "ignored_nodes": ignored_nodes,
        "ignored_edges": ignored_edges,
        "duplicate_keys": duplicate_keys,
    }


def _audit_metadata(topology: dict[str, Any], fallback_id: str | None) -> dict[str, Any]:
    audit = topology.get("audit") or {}
    return {
        "audit_id": audit.get("id") or fallback_id,
        "profile": audit.get("profile"),
        "interface": audit.get("interface"),
        "status": audit.get("status"),
    }


def compare_topologies(
    *,
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_audit_id: str | None = None,
    current_audit_id: str | None = None,
) -> dict[str, Any]:
    """Compare two topology views without making any network requests."""
    left = _snapshot(baseline, side="baseline")
    right = _snapshot(current, side="current")

    left_node_keys = set(left["nodes"])
    right_node_keys = set(right["nodes"])
    added_node_keys = sorted(right_node_keys - left_node_keys)
    removed_node_keys = sorted(left_node_keys - right_node_keys)
    shared_node_keys = sorted(left_node_keys & right_node_keys)

    changed_nodes = []
    for key in shared_node_keys:
        changes = _changed_fields(left["nodes"][key], right["nodes"][key], _NODE_FIELDS)
        if changes:
            changed_nodes.append(
                {
                    "key": key,
                    "match_basis": right["basis"].get(key) or left["basis"].get(key),
                    "before": _node_descriptor(key, left["nodes"][key], left["basis"].get(key, "unknown")),
                    "after": _node_descriptor(key, right["nodes"][key], right["basis"].get(key, "unknown")),
                    "changes": changes,
                }
            )

    left_edge_keys = set(left["edges"])
    right_edge_keys = set(right["edges"])
    added_edge_keys = sorted(right_edge_keys - left_edge_keys)
    removed_edge_keys = sorted(left_edge_keys - right_edge_keys)
    shared_edge_keys = sorted(left_edge_keys & right_edge_keys)

    changed_edges = []
    for key in shared_edge_keys:
        changes = _changed_fields(left["edges"][key], right["edges"][key], _EDGE_FIELDS)
        if changes:
            changed_edges.append(
                {
                    "key": key,
                    "before": _edge_descriptor(key, left["edges"][key], left["id_to_key"]),
                    "after": _edge_descriptor(key, right["edges"][key], right["id_to_key"]),
                    "changes": changes,
                }
            )

    left_segments = set(left["segments"])
    right_segments = set(right["segments"])
    added_segments = sorted(right_segments - left_segments)
    removed_segments = sorted(left_segments - right_segments)

    result = {
        "schema": "network-topology-diff",
        "schema_version": 1,
        "generated_at": _utc_now(),
        "baseline": _audit_metadata(baseline, baseline_audit_id),
        "current": _audit_metadata(current, current_audit_id),
        "summary": {
            "segments_added": len(added_segments),
            "segments_removed": len(removed_segments),
            "nodes_added": len(added_node_keys),
            "nodes_removed": len(removed_node_keys),
            "nodes_changed": len(changed_nodes),
            "edges_added": len(added_edge_keys),
            "edges_removed": len(removed_edge_keys),
            "edges_changed": len(changed_edges),
            "ignored_unstable_nodes": left["ignored_nodes"] + right["ignored_nodes"],
            "ignored_unstable_edges": left["ignored_edges"] + right["ignored_edges"],
            "duplicate_identity_keys": left["duplicate_keys"] + right["duplicate_keys"],
        },
        "segments": {
            "added": added_segments,
            "removed": removed_segments,
        },
        "nodes": {
            "added": [
                _node_descriptor(key, right["nodes"][key], right["basis"][key])
                for key in added_node_keys
            ],
            "removed": [
                _node_descriptor(key, left["nodes"][key], left["basis"][key])
                for key in removed_node_keys
            ],
            "changed": changed_nodes,
        },
        "edges": {
            "added": [
                _edge_descriptor(key, right["edges"][key], right["id_to_key"])
                for key in added_edge_keys
            ],
            "removed": [
                _edge_descriptor(key, left["edges"][key], left["id_to_key"])
                for key in removed_edge_keys
            ],
            "changed": changed_edges,
        },
        "warnings": [],
    }
    if result["summary"]["duplicate_identity_keys"]:
        result["warnings"].append(
            "В одном из topology обнаружены повторяющиеся стабильные identity keys; такие узлы не были автоматически склеены."
        )
    if result["summary"]["ignored_unstable_nodes"]:
        result["warnings"].append(
            "Multicast groups и route-gap placeholders исключены из historical diff как нестабильные визуальные сущности."
        )
    return result
