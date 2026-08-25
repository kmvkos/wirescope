"""Decorate topology with persisted routed-scope trace evidence.

Route evidence is intentionally directional.  For a routed target, the kernel
next-hop belongs to the *source* segment used by WireScope; it is not the
"gateway of" the remote target network.  This module corrects that distinction
before adding observed traceroute/tracepath hops.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
from typing import Any

from sqlalchemy import select

from persistence.models import ArtifactModel


def decorate_upstream_topology(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    documents = _route_trace_documents(services, audit_id)
    if not documents:
        topology.setdefault("upstream", {"trace_artifacts": 0, "traces": 0, "reached": 0})
        return topology

    trace_count = 0
    reached_count = 0
    artifact_ids: list[str] = []
    for artifact_id, document in documents:
        artifact_ids.append(artifact_id)
        contexts = _route_contexts(document)
        for context in contexts:
            _correct_routed_gateway(topology, context)
        for trace_index, trace in enumerate(document.get("traces") or []):
            if not isinstance(trace, dict) or trace.get("status") != "completed":
                continue
            trace_count += 1
            if trace.get("reached_target"):
                reached_count += 1
            _decorate_trace(
                topology,
                trace,
                artifact_id=artifact_id,
                trace_index=trace_index,
                tool=str(document.get("tool") or "route-trace"),
            )
        for warning in document.get("warnings") or []:
            _append_unique(topology.setdefault("warnings", []), str(warning))

    topology["upstream"] = {
        "trace_artifacts": len(documents),
        "artifact_ids": artifact_ids,
        "traces": trace_count,
        "reached": reached_count,
        "confidence": "observed",
        "provenance": ["route-trace"],
    }
    _sync_routing_metadata(topology)
    _refresh_summary(topology)
    return topology


def decorate_global_upstream_topology(services, topology: dict[str, Any]) -> dict[str, Any]:
    audit_ids = [str(item.get("id")) for item in topology.get("audits") or [] if item.get("id")]
    total_traces = 0
    artifacts: list[str] = []
    for audit_id in audit_ids:
        documents = _route_trace_documents(services, audit_id)
        for artifact_id, document in documents:
            artifacts.append(artifact_id)
            for context in _route_contexts(document):
                _correct_routed_gateway(topology, context)
            for trace_index, trace in enumerate(document.get("traces") or []):
                if not isinstance(trace, dict) or trace.get("status") != "completed":
                    continue
                total_traces += 1
                _decorate_trace(
                    topology,
                    trace,
                    artifact_id=artifact_id,
                    trace_index=trace_index,
                    tool=str(document.get("tool") or "route-trace"),
                )
    topology["upstream"] = {
        "trace_artifacts": len(set(artifacts)),
        "artifact_ids": sorted(set(artifacts)),
        "traces": total_traces,
        "confidence": "observed",
        "provenance": ["route-trace"],
    }
    _sync_routing_metadata(topology)
    _refresh_summary(topology)
    return topology


def _route_trace_documents(services, audit_id: str) -> list[tuple[str, dict[str, Any]]]:
    with services.database.session() as session:
        rows = session.scalars(
            select(ArtifactModel)
            .where(
                ArtifactModel.audit_id == audit_id,
                ArtifactModel.artifact_type == "route_trace_result",
            )
            .order_by(ArtifactModel.created_at.desc())
            .limit(8)
        ).all()
        artifact_ids = [row.id for row in rows]

    documents: list[tuple[str, dict[str, Any]]] = []
    for artifact_id in artifact_ids:
        try:
            record = services.jobs.artifact(artifact_id)
            document = services.evidence.read_json(record)
        except Exception:
            continue
        if isinstance(document, dict) and document.get("schema") == "route-trace-result":
            documents.append((artifact_id, document))
    return documents


def _route_contexts(document: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    raw_rows = [*(document.get("targets") or []), *(document.get("traces") or [])]
    for raw in raw_rows:
        if not isinstance(raw, dict):
            continue
        context = {
            "target": str(raw.get("target") or ""),
            "scope_target": str(raw.get("scope_target") or ""),
            "source_address": str(raw.get("source_address") or ""),
            "gateway": str(raw.get("gateway") or ""),
        }
        key = tuple(context[name] for name in ("target", "scope_target", "source_address", "gateway"))
        if key in seen or not context["scope_target"]:
            continue
        seen.add(key)
        rows.append(context)
    return rows


def _correct_routed_gateway(topology: dict[str, Any], context: dict[str, Any]) -> None:
    """Move a routed target's next-hop from the remote segment to the source segment."""
    target_segment_id = _segment_for_scope(
        topology,
        context.get("scope_target", ""),
        context.get("target", ""),
    )
    gateway = context.get("gateway") or ""
    source_address = context.get("source_address") or ""
    if not target_segment_id or not gateway:
        return

    source_segment_id = _ensure_source_segment(topology, source_address)
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    aliases = _address_aliases(nodes)
    gateway_id = aliases.get(gateway)
    if gateway_id is None:
        gateway_id = f"route-hop:{gateway}"
        nodes.append(
            {
                "id": gateway_id,
                "kind": "network-device",
                "label": gateway,
                "roles": ["gateway", "router"],
                "addresses": [gateway],
                "names": [],
                "confidence": "confirmed",
                "routing_confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
                "connected_segments": [source_segment_id] if source_segment_id else [],
            }
        )
    else:
        node = _node_by_id(nodes, gateway_id)
        if node is not None:
            _append_unique(node.setdefault("roles", []), "gateway")
            _append_unique(node.setdefault("roles", []), "router")
            _append_unique(node.setdefault("provenance", []), "confirmed-scope-route")
            node["routing_confidence"] = "confirmed"
            connected = node.setdefault("connected_segments", [])
            while target_segment_id in connected:
                connected.remove(target_segment_id)
            if source_segment_id:
                _append_unique(connected, source_segment_id)

    # The old segment-aware pass attached the route next-hop to the *target*
    # segment.  Remove exactly that routed edge, but keep unrelated DHCP/LLDP
    # or independently-confirmed topology evidence intact.
    kept_edges = []
    for edge in edges:
        if (
            edge.get("relation") == "segment_gateway"
            and edge.get("source") == target_segment_id
            and edge.get("target") == gateway_id
            and "confirmed-scope-route" in set(edge.get("provenance") or [])
        ):
            continue
        kept_edges.append(edge)
    topology["edges"] = kept_edges

    target_segment = _segment_by_id(topology, target_segment_id)
    if target_segment is not None:
        target_segment["gateways"] = [
            value for value in (target_segment.get("gateways") or []) if str(value) != gateway
        ]
        target_segment["route_via"] = gateway
        target_segment["route_source_address"] = source_address or None
        _append_unique(target_segment.setdefault("provenance", []), "confirmed-scope-route")

    if not source_segment_id:
        _append_unique(
            topology.setdefault("warnings", []),
            f"Route to {context.get('scope_target')} uses next-hop {gateway}, but the source subnet prefix for {source_address or 'the selected interface'} was not retained; the global L3 origin is therefore incomplete.",
        )
        return

    source_segment = _segment_by_id(topology, source_segment_id)
    if source_segment is not None:
        _append_unique(source_segment.setdefault("gateways", []), gateway)
        source_segment["source_address"] = source_address or source_segment.get("source_address")

    edges = topology.setdefault("edges", [])
    if not any(
        edge.get("relation") == "segment_gateway"
        and edge.get("source") == source_segment_id
        and edge.get("target") == gateway_id
        for edge in edges
    ):
        edges.append(
            {
                "id": f"edge:source-gateway:{source_segment_id}:{gateway_id}",
                "source": source_segment_id,
                "target": gateway_id,
                "relation": "segment_gateway",
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
                "segment_id": source_segment_id,
                "segment_ids": [source_segment_id],
                "route_target_segment": target_segment_id,
            }
        )


def _decorate_trace(
    topology: dict[str, Any],
    trace: dict[str, Any],
    *,
    artifact_id: str,
    trace_index: int,
    tool: str,
) -> None:
    scope_target = str(trace.get("scope_target") or "")
    target = str(trace.get("target") or "")
    target_segment_id = _segment_for_scope(topology, scope_target, target)
    if not target_segment_id:
        return

    source_address = str(trace.get("source_address") or "")
    gateway = str(trace.get("gateway") or "")
    source_segment_id = _ensure_source_segment(topology, source_address)
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    alias = _address_aliases(nodes)

    gateway_id = alias.get(gateway) if gateway else None
    previous = source_segment_id or gateway_id
    if source_segment_id and gateway_id:
        previous = source_segment_id

    responded_hops = 0
    last_node_id: str | None = None
    for raw_hop in trace.get("hops") or []:
        if not isinstance(raw_hop, dict):
            continue
        ttl = int(raw_hop.get("ttl") or 0)
        if ttl <= 0:
            continue
        address = raw_hop.get("address")
        if address:
            address = str(address)
            node_id = alias.get(address)
            if node_id is None:
                node_id = f"route-hop:{address}"
                nodes.append(
                    {
                        "id": node_id,
                        "kind": "network-device",
                        "label": address,
                        "roles": ["route-hop"],
                        "addresses": [address],
                        "names": [],
                        "confidence": "observed",
                        "provenance": [tool, "route-trace"],
                        "route_trace_artifact_ids": [artifact_id],
                    }
                )
                alias[address] = node_id
            else:
                node = _node_by_id(nodes, node_id)
                if node is not None:
                    _append_unique(node.setdefault("roles", []), "route-hop")
                    _append_unique(node.setdefault("provenance", []), tool)
                    _append_unique(node.setdefault("provenance", []), "route-trace")
                    _append_unique(node.setdefault("route_trace_artifact_ids", []), artifact_id)
            responded_hops += 1
        else:
            node_id = f"route-gap:{artifact_id}:{trace_index}:{ttl}"
            if not any(item.get("id") == node_id for item in nodes):
                nodes.append(
                    {
                        "id": node_id,
                        "kind": "route-gap",
                        "label": f"TTL {ttl} · нет ответа",
                        "roles": ["unknown-hop"],
                        "addresses": [],
                        "names": [],
                        "confidence": "observed",
                        "provenance": [tool, "route-trace-timeout"],
                        "route_trace_artifact_ids": [artifact_id],
                    }
                )

        # The first observed hop is commonly the already-confirmed next-hop.
        # Reuse that node/edge instead of drawing a duplicate route_hop.
        duplicate_gateway = bool(
            previous
            and gateway_id
            and node_id == gateway_id
            and any(
                edge.get("relation") == "segment_gateway"
                and edge.get("source") == previous
                and edge.get("target") == gateway_id
                for edge in edges
            )
        )
        if previous and previous != node_id and not duplicate_gateway:
            edge_id = f"edge:route-trace:{artifact_id}:{trace_index}:{ttl}"
            if not any(edge.get("id") == edge_id for edge in edges):
                edges.append(
                    {
                        "id": edge_id,
                        "source": previous,
                        "target": node_id,
                        "relation": "route_hop",
                        "layer": "l3",
                        "confidence": "observed",
                        "provenance": [tool, "route-trace"],
                        "segment_ids": [value for value in (source_segment_id, target_segment_id) if value],
                        "ttl": ttl,
                        "rtt_ms": raw_hop.get("rtt_ms"),
                        "trace_target": target,
                        "artifact_id": artifact_id,
                    }
                )
        previous = node_id
        last_node_id = node_id

    if responded_hops == 0 or not trace.get("reached_target") or not last_node_id:
        return

    # A reached representative host proves that the observed trace arrived in
    # the target segment.  This is an observed association, not a claim that
    # every host in the subnet follows the same path.
    if last_node_id != target_segment_id and not any(
        edge.get("relation") == "route_target"
        and edge.get("source") == last_node_id
        and edge.get("target") == target_segment_id
        for edge in edges
    ):
        edges.append(
            {
                "id": f"edge:route-target:{artifact_id}:{trace_index}",
                "source": last_node_id,
                "target": target_segment_id,
                "relation": "route_target",
                "layer": "l3",
                "confidence": "observed",
                "provenance": [tool, "route-trace"],
                "segment_ids": [target_segment_id],
                "trace_target": target,
                "artifact_id": artifact_id,
            }
        )


def _ensure_source_segment(topology: dict[str, Any], source_address: str) -> str | None:
    if not source_address:
        return None
    try:
        source_ip = ipaddress.ip_address(source_address)
    except ValueError:
        return None

    existing = _segment_for_address(topology, source_ip)
    if existing:
        return existing

    # Derive the network only from an actual CIDR retained on the WireScope
    # interface node.  Never invent a /24 (or any other prefix) from an IP.
    interface_network = None
    sensor_id = None
    for node in topology.get("nodes") or []:
        if node.get("kind") != "wirescope":
            continue
        for raw in node.get("addresses") or []:
            text = str(raw)
            if "/" not in text:
                continue
            try:
                interface = ipaddress.ip_interface(text)
            except ValueError:
                continue
            if interface.ip == source_ip:
                interface_network = interface.network
                sensor_id = str(node.get("id") or "") or None
                break
        if interface_network is not None:
            break
    if interface_network is None:
        return None

    segment_id = f"segment:{interface_network}"
    segment = {
        "id": segment_id,
        "kind": "subnet" if interface_network.prefixlen < interface_network.max_prefixlen else "host-scope",
        "label": str(interface_network),
        "network": str(interface_network),
        "family": interface_network.version,
        "prefix_length": interface_network.prefixlen,
        "members": [sensor_id] if sensor_id else [],
        "gateways": [],
        "interface": str((topology.get("audit") or {}).get("interface") or ""),
        "source_address": source_address,
        "directly_connected": True,
        "confidence": "confirmed",
        "provenance": ["environment-interface-address", "confirmed-scope-route"],
        "source_segment": True,
    }
    topology.setdefault("segments", []).append(segment)
    if not any(node.get("id") == segment_id for node in topology.get("nodes") or []):
        topology.setdefault("nodes", []).append(
            {
                "id": segment_id,
                "kind": "segment",
                "label": str(interface_network),
                "network": str(interface_network),
                "family": interface_network.version,
                "roles": ["subnet", "route-source"],
                "addresses": [],
                "names": [],
                "member_count": 1 if sensor_id else 0,
                "segment_ids": [segment_id],
                "confidence": "confirmed",
                "provenance": ["environment-interface-address", "confirmed-scope-route"],
            }
        )
    return segment_id


def _segment_for_scope(topology: dict[str, Any], scope_target: str, target: str) -> str | None:
    try:
        target_ip = ipaddress.ip_address(target) if target else None
    except ValueError:
        target_ip = None
    try:
        scope_network = ipaddress.ip_network(scope_target, strict=False) if scope_target else None
    except ValueError:
        scope_network = None

    for segment in topology.get("segments") or []:
        segment_id = str(segment.get("id") or "")
        network_text = str(segment.get("network") or "")
        if not segment_id or not network_text:
            continue
        if scope_network is not None:
            try:
                candidate = ipaddress.ip_network(network_text, strict=False)
                if candidate == scope_network:
                    return segment_id
            except ValueError:
                pass
        if target_ip is not None:
            try:
                if target_ip in ipaddress.ip_network(network_text, strict=False):
                    return segment_id
            except ValueError:
                pass
    return None


def _segment_for_address(topology: dict[str, Any], address: ipaddress._BaseAddress) -> str | None:
    best: tuple[int, str] | None = None
    for segment in topology.get("segments") or []:
        segment_id = str(segment.get("id") or "")
        network_text = str(segment.get("network") or "")
        if not segment_id or not network_text:
            continue
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            candidate = (network.prefixlen, segment_id)
            if best is None or candidate[0] > best[0]:
                best = candidate
    return best[1] if best else None


def _segment_by_id(topology: dict[str, Any], segment_id: str) -> dict[str, Any] | None:
    return next(
        (segment for segment in topology.get("segments") or [] if str(segment.get("id") or "") == segment_id),
        None,
    )


def _node_by_id(nodes: list[dict[str, Any]], node_id: str) -> dict[str, Any] | None:
    return next((node for node in nodes if str(node.get("id") or "") == node_id), None)


def _address_aliases(nodes: list[dict[str, Any]]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        node_id = str(node.get("id") or "")
        for address in node.get("addresses") or []:
            aliases[str(address).split("/", 1)[0]] = node_id
    return aliases


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _sync_routing_metadata(topology: dict[str, Any]) -> None:
    routing = topology.get("routing")
    if not isinstance(routing, dict):
        return
    node_by_id = {
        str(node.get("id")): node
        for node in topology.get("nodes") or []
        if node.get("id")
    }
    for key in ("routers", "router_candidates"):
        rows = routing.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            node = node_by_id.get(str(row.get("node_id") or ""))
            if node is None:
                continue
            row["connected_segments"] = list(node.get("connected_segments") or [])
            row["confidence"] = node.get("routing_confidence") or row.get("confidence")


def _refresh_summary(topology: dict[str, Any]) -> None:
    edges = topology.get("edges") or []
    nodes = topology.get("nodes") or []
    summary = topology.setdefault("summary", {})
    summary["nodes"] = len(nodes)
    summary["edges"] = len(edges)
    summary["segments"] = len(topology.get("segments") or [])
    summary["route_hops"] = sum(1 for node in nodes if "route-hop" in set(node.get("roles") or []))
    summary["route_gaps"] = sum(1 for node in nodes if node.get("kind") == "route-gap")
    summary["confidence"] = dict(Counter(str(edge.get("confidence") or "unknown") for edge in edges))
    summary["layers"] = dict(Counter(str(edge.get("layer") or "general") for edge in edges))
