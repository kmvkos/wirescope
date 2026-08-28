"""Readable presentation projection for dense PCAP communication graphs.

Raw communication nodes/edges remain in canonical topology and in the Evidence
view. The operator Traffic projection suppresses protocol bookkeeping that is
better represented as identity/L2 evidence and collapses unrelated external
peers into one Internet node.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any


EXTERNAL_AGGREGATION_THRESHOLD = 2


def _bare(value: Any) -> str:
    return str(value or "").split("/", 1)[0].strip()


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(_bare(value))
    except ValueError:
        return None


def _is_external_peer(node: dict[str, Any]) -> bool:
    if node.get("pcap_local_identity"):
        return False
    if node.get("pcap_state") == "external_peer":
        return True
    if node.get("kind") not in {"endpoint", "external-endpoint"}:
        return False
    if "pcap" not in set(node.get("provenance") or []):
        return False
    addresses = [_ip(value) for value in node.get("addresses") or []]
    addresses = [value for value in addresses if value is not None]
    return bool(addresses) and all(
        value.is_global and not value.is_multicast for value in addresses
    )


def _protocol_names(edge: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for item in edge.get("protocols") or []:
        if isinstance(item, dict):
            value = item.get("name")
        else:
            value = item
        if value:
            result.add(str(value).lower())
    return result


def _is_arp_only(edge: dict[str, Any]) -> bool:
    protocols = _protocol_names(edge)
    return bool(protocols) and protocols <= {"arp"}


def _merge_unique(current: list[Any], incoming: list[Any], *, limit: int = 32) -> list[Any]:
    result = list(current)
    for item in incoming:
        if item not in result:
            result.append(item)
        if len(result) >= limit:
            break
    return result


def _referenced_nodes(edges: dict[str, dict[str, Any]], edge_ids: list[str]) -> set[str]:
    result: set[str] = set()
    for edge_id in edge_ids:
        edge = edges.get(edge_id)
        if not edge:
            continue
        for endpoint in (edge.get("source"), edge.get("target")):
            if endpoint:
                result.add(str(endpoint))
    return result


def decorate_traffic_presentation(topology: dict[str, Any]) -> dict[str, Any]:
    """Replace only the UI Traffic projection; preserve canonical raw evidence."""
    presentation = topology.get("presentation") or {}
    views = presentation.get("views") or {}
    traffic = views.get("traffic")
    overlay = topology.get("overlay") or {}
    if not isinstance(traffic, dict) or not overlay:
        return topology

    nodes = topology.get("nodes") or []
    edges = topology.get("edges") or []
    node_by_id = {
        str(node.get("id")): node
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    }
    edge_by_id = {
        str(edge.get("id")): edge
        for edge in edges
        if isinstance(edge, dict) and edge.get("id")
    }

    raw_node_ids = {
        str(value) for value in (traffic.get("node_ids") or []) if str(value) in node_by_id
    }
    raw_edge_ids = [
        str(value) for value in (traffic.get("edge_ids") or []) if str(value) in edge_by_id
    ]
    external_ids = {
        node_id
        for node_id in raw_node_ids
        if _is_external_peer(node_by_id[node_id])
    }
    aggregate_external = len(external_ids) >= EXTERNAL_AGGREGATION_THRESHOLD

    job_id = str(overlay.get("traffic_analysis_job_id") or "pcap")
    group_id = f"pcap-external-group:{job_id[:12]}"
    if aggregate_external:
        group_node = {
            "id": group_id,
            "kind": "external-group",
            "label": "Internet / внешние узлы",
            "roles": ["external-peers", "internet"],
            "addresses": [],
            "names": [],
            "provenance": ["pcap-presentation"],
            "confidence": "observed",
            "presentation_only": True,
            "external_peer_count": len(external_ids),
            "collapsed_node_ids": sorted(external_ids),
        }
        topology.setdefault("nodes", []).append(group_node)
        node_by_id[group_id] = group_node

    retained_edge_ids: list[str] = []
    aggregates: defaultdict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "protocols": [],
            "ports": [],
            "external_peers": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )
    external_to_external_edges = 0
    arp_edges_hidden = 0
    hidden_endpoint_edges = 0

    for edge_id in raw_edge_ids:
        edge = edge_by_id[edge_id]
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")

        # Presentation already removed broadcast/multicast nodes. Do not leave
        # their counterpart as an orphan card by retaining an edge whose other
        # endpoint is no longer part of the view.
        if source not in raw_node_ids or target not in raw_node_ids:
            hidden_endpoint_edges += 1
            continue

        # ARP request/reply semantics now live in endpoint/identity evidence.
        # Drawing them again as user communications duplicates information and
        # is the main source of MAC-card noise in router captures.
        if _is_arp_only(edge):
            arp_edges_hidden += 1
            continue

        source_external = source in external_ids
        target_external = target in external_ids
        if not aggregate_external:
            retained_edge_ids.append(edge_id)
            continue

        if not source_external and not target_external:
            retained_edge_ids.append(edge_id)
            continue
        if source_external and target_external:
            external_to_external_edges += 1
            continue

        internal_id = target if source_external else source
        external_id = source if source_external else target
        if internal_id not in node_by_id:
            continue
        item = aggregates[internal_id]
        item["packets"] += int(edge.get("packets") or 0)
        item["bytes"] += int(edge.get("bytes") or 0)
        item["protocols"] = _merge_unique(item["protocols"], list(edge.get("protocols") or []))
        item["ports"] = _merge_unique(item["ports"], list(edge.get("ports") or []))
        item["external_peers"].add(external_id)
        first = edge.get("first_seen")
        last = edge.get("last_seen")
        if first:
            item["first_seen"] = first if not item["first_seen"] else min(str(item["first_seen"]), str(first))
        if last:
            item["last_seen"] = last if not item["last_seen"] else max(str(item["last_seen"]), str(last))

    synthetic_edge_ids: list[str] = []
    if aggregate_external:
        for index, (internal_id, item) in enumerate(
            sorted(
                aggregates.items(),
                key=lambda pair: (int(pair[1]["bytes"]), int(pair[1]["packets"])),
                reverse=True,
            ),
            start=1,
        ):
            edge_id = f"pcap-presentation-edge:{job_id[:8]}:{index}"
            edge = {
                "id": edge_id,
                "source": internal_id,
                "target": group_id,
                "relation": "communication",
                "layer": "traffic",
                "confidence": "observed",
                "provenance": ["pcap-presentation"],
                "presentation_only": True,
                "aggregated": True,
                "packets": item["packets"],
                "bytes": item["bytes"],
                "protocols": item["protocols"],
                "ports": item["ports"],
                "external_peer_count": len(item["external_peers"]),
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
            }
            topology.setdefault("edges", []).append(edge)
            edge_by_id[edge_id] = edge
            synthetic_edge_ids.append(edge_id)

    final_edge_ids = retained_edge_ids + synthetic_edge_ids
    visible_nodes = _referenced_nodes(edge_by_id, final_edge_ids)
    # A selected capture with only filtered ARP/broadcast evidence should render
    # as an empty traffic communication view rather than a wall of orphan MACs.
    visible_nodes.intersection_update(set(node_by_id))

    traffic["node_ids"] = sorted(visible_nodes)
    traffic["edge_ids"] = final_edge_ids
    traffic["external_peer_count"] = len(external_ids)
    traffic["external_peers_aggregated"] = aggregate_external
    traffic["external_group_node_id"] = group_id if aggregate_external else None
    traffic["raw_node_count"] = len(raw_node_ids)
    traffic["raw_edge_count"] = len(raw_edge_ids)
    traffic["visible_node_count"] = len(visible_nodes)
    traffic["visible_edge_count"] = len(final_edge_ids)
    traffic["arp_edges_hidden"] = arp_edges_hidden
    traffic["hidden_endpoint_edges"] = hidden_endpoint_edges
    traffic["external_to_external_edges_hidden"] = external_to_external_edges
    traffic["description"] = (
        "Наблюдавшиеся communications из выбранного PCAP. ARP отображается как identity/L2 evidence, "
        "broadcast/multicast не создаёт orphan-карточки, а внешние peers по умолчанию свёрнуты в Internet. "
        "Полный raw graph остаётся в представлении «Все evidence»."
    )

    suppressed = presentation.setdefault("suppressed", {})
    suppressed["external_peer_node_ids"] = sorted(external_ids) if aggregate_external else []
    suppressed["external_peer_count"] = len(external_ids)
    suppressed["arp_communication_edge_count"] = arp_edges_hidden
    suppressed["hidden_endpoint_edge_count"] = hidden_endpoint_edges
    return topology


__all__ = ["decorate_traffic_presentation"]
