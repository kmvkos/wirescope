"""Decorate topology with persisted routed-scope trace evidence."""

from __future__ import annotations

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
    segment_id = _segment_for_scope(topology, scope_target, target)
    if not segment_id:
        return

    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    alias = _address_aliases(nodes)
    previous = segment_id
    responded_hops = 0

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
                node = next((item for item in nodes if item.get("id") == node_id), None)
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

        # A confirmed segment_gateway already expresses segment -> first-hop
        # when traceroute's first response is the known gateway. Avoid drawing
        # a duplicate edge in that common case.
        duplicate_gateway = any(
            edge.get("relation") == "segment_gateway"
            and edge.get("source") == previous
            and edge.get("target") == node_id
            for edge in edges
        )
        if not duplicate_gateway:
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
                        "segment_ids": [segment_id],
                        "ttl": ttl,
                        "rtt_ms": raw_hop.get("rtt_ms"),
                        "trace_target": target,
                        "artifact_id": artifact_id,
                    }
                )
        previous = node_id

    if responded_hops == 0:
        return


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


def _refresh_summary(topology: dict[str, Any]) -> None:
    edges = topology.get("edges") or []
    nodes = topology.get("nodes") or []
    summary = topology.setdefault("summary", {})
    summary["nodes"] = len(nodes)
    summary["edges"] = len(edges)
    summary["route_hops"] = sum(1 for node in nodes if "route-hop" in set(node.get("roles") or []))
    summary["route_gaps"] = sum(1 for node in nodes if node.get("kind") == "route-gap")
