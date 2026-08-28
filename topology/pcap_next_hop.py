"""Project normalized PCAP next-hop evidence into structural/L3 topology.

This decorator consumes only explicit `next_hop_evidence` produced by the traffic
analyzer. It never derives topology from arbitrary communication edges here.
"""

from __future__ import annotations

from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound


class PcapNextHopSourceError(RuntimeError):
    pass


def _bare(value: Any) -> str:
    return str(value or "").split("/", 1)[0].strip()


def _merge_unique(current: list[Any], incoming: list[Any]) -> list[Any]:
    result = list(current)
    for item in incoming:
        if item not in result:
            result.append(item)
    return result


def _load_document(services, job_id: str) -> dict[str, Any]:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise PcapNextHopSourceError(f"Traffic analysis not found: {job_id}") from exc
    if job.type != "traffic_analysis" or job.status != JobStatus.COMPLETED or not job.result_reference:
        raise PcapNextHopSourceError("Traffic analysis is not completed")
    try:
        artifact = services.jobs.artifact(job.result_reference)
        document = services.evidence.read_json(artifact)
    except (EntityNotFound, JobExecutionError) as exc:
        raise PcapNextHopSourceError("Traffic analysis result could not be loaded") from exc
    return document if isinstance(document, dict) else {}


def _aliases(topology: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for node in topology.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        values = [node.get("mac"), node.get("label")]
        values.extend(node.get("addresses") or [])
        values.extend(node.get("names") or [])
        for value in values:
            key = _bare(value).lower()
            if key:
                result.setdefault(key, node)
    return result


def _ensure_node(
    topology: dict[str, Any],
    aliases: dict[str, dict[str, Any]],
    *,
    address: str,
    mac: str | None,
    role: str,
    job_id: str,
) -> dict[str, Any]:
    node = aliases.get(address.lower())
    if node is None and mac:
        node = aliases.get(mac.lower())
    if node is None:
        node = {
            "id": f"pcap-l3:{job_id[:8]}:{address}",
            "kind": "network-device" if role == "router" else "endpoint",
            "label": address,
            "roles": [],
            "addresses": [address],
            "names": [],
            "provenance": ["pcap-next-hop"],
            "confidence": "observed",
            "pcap_only": True,
            "pcap_local_identity": True,
        }
        topology.setdefault("nodes", []).append(node)
    node["roles"] = _merge_unique(node.get("roles") or [], [role])
    node["provenance"] = _merge_unique(node.get("provenance") or [], ["pcap-next-hop"])
    node["pcap_local_identity"] = True
    if role == "router":
        if node.get("kind") == "endpoint":
            node["kind"] = "network-device"
        node["roles"] = _merge_unique(node.get("roles") or [], ["next-hop"])
    if mac:
        node["mac"] = node.get("mac") or mac
    aliases[address.lower()] = node
    if mac:
        aliases[mac.lower()] = node
    return node


def _edge_exists(topology: dict[str, Any], source: str, target: str) -> bool:
    return any(
        isinstance(edge, dict)
        and edge.get("relation") == "l3_next_hop"
        and edge.get("source") == source
        and edge.get("target") == target
        for edge in topology.get("edges") or []
    )


def decorate_pcap_next_hops(
    services,
    topology: dict[str, Any],
    *,
    traffic_analysis_job_id: str | None,
) -> dict[str, Any]:
    if not traffic_analysis_job_id or not topology.get("overlay"):
        return topology

    document = _load_document(services, traffic_analysis_job_id)
    evidence = document.get("next_hop_evidence") or {}
    candidates = evidence.get("candidates") or []
    if not isinstance(candidates, list) or not candidates:
        overlay = dict(topology.get("overlay") or {})
        overlay["next_hop"] = {
            "candidate_count": int(evidence.get("candidate_count") or 0),
            "high_confidence_count": int(evidence.get("high_confidence_count") or 0),
        }
        topology["overlay"] = overlay
        return topology

    aliases = _aliases(topology)
    added_edges = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        source_ip = _bare(candidate.get("source_ip"))
        next_hop_ip = _bare(candidate.get("next_hop_ip"))
        next_hop_mac = str(candidate.get("next_hop_mac") or "").lower() or None
        if not source_ip or not next_hop_ip or source_ip == next_hop_ip:
            continue

        source_node = _ensure_node(
            topology,
            aliases,
            address=source_ip,
            mac=None,
            role="host",
            job_id=traffic_analysis_job_id,
        )
        hop_node = _ensure_node(
            topology,
            aliases,
            address=next_hop_ip,
            mac=next_hop_mac,
            role="router",
            job_id=traffic_analysis_job_id,
        )
        if _edge_exists(topology, str(source_node["id"]), str(hop_node["id"])):
            continue

        edge_id = f"pcap-next-hop-edge:{traffic_analysis_job_id[:8]}:{added_edges + 1}"
        topology.setdefault("edges", []).append(
            {
                "id": edge_id,
                "source": source_node["id"],
                "target": hop_node["id"],
                "relation": "l3_next_hop",
                "layer": "l3",
                "confidence": "observed",
                "evidence_confidence": candidate.get("confidence"),
                "provenance": ["pcap-next-hop"],
                "evidence_count": int(candidate.get("flow_count") or 0),
                "remote_destination_count": int(candidate.get("remote_destination_count") or 0),
                "packets": int(candidate.get("packets") or 0),
                "bytes": int(candidate.get("bytes") or 0),
                "protocols": list(candidate.get("protocols") or []),
                "first_seen": candidate.get("first_seen"),
                "last_seen": candidate.get("last_seen"),
                "limitations": [
                    "Связь означает immediate Ethernet/L3 next hop, видимый в точке PCAP, а не полный маршрут до внешних адресов."
                ],
            }
        )
        added_edges += 1

    overlay = dict(topology.get("overlay") or {})
    overlay["next_hop"] = {
        "candidate_count": int(evidence.get("candidate_count") or 0),
        "high_confidence_count": int(evidence.get("high_confidence_count") or 0),
        "topology_edges_added": added_edges,
        "ambiguous_count": len(evidence.get("ambiguous") or []),
    }
    topology["overlay"] = overlay
    return topology


__all__ = ["PcapNextHopSourceError", "decorate_pcap_next_hops"]
