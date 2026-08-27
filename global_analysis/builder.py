"""Deterministic correlation of persisted WireScope analysis sources.

This module never opens a live socket, re-reads a PCAP, or launches a scanner.
It correlates already persisted inventory/findings, one explicitly selected
traffic-analysis result, and the canonical network topology for the audit.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from reports.sources import load_report_source
from topology import TopologySourceError, build_topology


ASSET_IDENTITY_RULE = "GA-ASSET-IDENTITY-001"
SERVICE_USAGE_RULE = "GA-SERVICE-USAGE-001"
INVENTORY_COVERAGE_RULE = "GA-INVENTORY-TRAFFIC-COVERAGE-001"
EXTERNAL_COMMUNICATION_RULE = "GA-EXTERNAL-COMMUNICATION-001"
FINDING_RELEVANCE_RULE = "GA-FINDING-TRAFFIC-RELEVANCE-001"

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


class GlobalAnalysisSourceError(RuntimeError):
    """Selected persisted source cannot be used for global analysis."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_id(rule_id: str, *parts: Any) -> str:
    payload = json.dumps([rule_id, *parts], sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{rule_id.lower()}:{digest}"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _safe_ip(value: Any) -> ipaddress._BaseAddress | None:
    text = _text(value)
    if not text:
        return None
    try:
        return ipaddress.ip_address(text.split("/", 1)[0])
    except ValueError:
        return None


def _canonical_mac(value: Any) -> str | None:
    text = (_text(value) or "").lower().replace("-", ":")
    return text if _MAC_RE.fullmatch(text) else None


def _traffic_source(services, job_id: str) -> tuple[Any, dict[str, Any]]:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise GlobalAnalysisSourceError(f"Traffic analysis not found: {job_id}") from exc
    if job.type != "traffic_analysis":
        raise GlobalAnalysisSourceError("Selected source is not a traffic analysis job")
    if job.status != JobStatus.COMPLETED or not job.result_reference:
        raise GlobalAnalysisSourceError("Selected traffic analysis is not completed")
    try:
        artifact = services.jobs.artifact(job.result_reference)
        if artifact.job_id != job.id or artifact.artifact_type != "traffic_analysis_result":
            raise GlobalAnalysisSourceError("Traffic analysis result reference is inconsistent")
        document = services.evidence.read_json(artifact)
    except EntityNotFound as exc:
        raise GlobalAnalysisSourceError("Traffic analysis result artifact was not found") from exc
    except JobExecutionError as exc:
        raise GlobalAnalysisSourceError("Traffic analysis result could not be read") from exc
    if not isinstance(document, dict) or document.get("schema") != "traffic-analysis":
        raise GlobalAnalysisSourceError("Selected traffic analysis has an unsupported document contract")
    return job, document


def build_global_analysis(
    services,
    audit_id: str,
    *,
    traffic_analysis_job_id: str,
) -> dict[str, Any]:
    """Build a deterministic analysis package from persisted sources only."""
    audit = services.jobs.get_audit(audit_id)
    report_source = load_report_source(
        audit=audit,
        database=services.database,
        inventory=services.inventory,
        findings=services.findings,
        evidence_store=services.evidence,
    )
    traffic_job, traffic_document = _traffic_source(services, traffic_analysis_job_id)
    try:
        topology = build_topology(
            services,
            audit_id,
            traffic_analysis_job_id=traffic_analysis_job_id,
        )
    except TopologySourceError as exc:
        raise GlobalAnalysisSourceError(str(exc)) from exc

    return assemble_global_analysis(
        audit={
            "id": audit.id,
            "profile": audit.profile,
            "interface": audit.interface,
            "status": audit.status.value,
        },
        assets=[item.model_dump(mode="json") for item in report_source.assets],
        services=[item.model_dump(mode="json") for item in report_source.services],
        findings=[item.model_dump(mode="json") for item in report_source.findings],
        traffic_job={
            "id": traffic_job.id,
            "audit_id": traffic_job.audit_id,
            "result_reference": traffic_job.result_reference,
        },
        traffic_analysis=traffic_document,
        topology=topology,
        source_warnings=list(report_source.warnings or []),
        source_truncated=bool(report_source.truncated),
    )


def assemble_global_analysis(
    *,
    audit: dict[str, Any],
    assets: list[dict[str, Any]],
    services: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    traffic_job: dict[str, Any],
    traffic_analysis: dict[str, Any],
    topology: dict[str, Any],
    source_warnings: list[str] | None = None,
    source_truncated: bool = False,
) -> dict[str, Any]:
    """Pure correlation function used by API and fixture-based tests."""
    source_warnings = list(source_warnings or [])
    topology_segments = _topology_networks(topology)

    by_ip: dict[str, list[str]] = {}
    by_mac: dict[str, list[str]] = {}
    asset_by_id: dict[str, dict[str, Any]] = {}
    for asset in assets:
        asset_id = str(asset.get("id") or "")
        if not asset_id:
            continue
        asset_by_id[asset_id] = asset
        for raw in asset.get("addresses") or []:
            parsed = _safe_ip(raw)
            if parsed is not None:
                by_ip.setdefault(str(parsed), []).append(asset_id)
        mac = _canonical_mac(asset.get("mac"))
        if mac:
            by_mac.setdefault(mac, []).append(asset_id)

    graph = traffic_analysis.get("communications_graph") or {}
    graph_nodes = graph.get("nodes") if isinstance(graph, dict) else []
    graph_edges = graph.get("edges") if isinstance(graph, dict) else []
    graph_nodes = graph_nodes if isinstance(graph_nodes, list) else []
    graph_edges = graph_edges if isinstance(graph_edges, list) else []

    endpoint_values: set[str] = set()
    endpoint_kind: dict[str, str] = {}
    for node in graph_nodes:
        if not isinstance(node, dict):
            continue
        endpoint = _text(node.get("id"))
        if not endpoint:
            continue
        endpoint_values.add(endpoint)
        endpoint_kind[endpoint] = str(node.get("kind") or "unknown")
    for edge in graph_edges:
        if not isinstance(edge, dict):
            continue
        for key in ("endpoint_a", "endpoint_b"):
            endpoint = _text(edge.get(key))
            if endpoint:
                endpoint_values.add(endpoint)

    endpoint_identity: list[dict[str, Any]] = []
    identity_by_endpoint: dict[str, dict[str, Any]] = {}
    observed_asset_ids: set[str] = set()
    identity_conflicts: list[dict[str, Any]] = []

    for endpoint in sorted(endpoint_values):
        match_basis = "unmatched"
        asset_id: str | None = None
        candidates: list[str] = []
        parsed_ip = _safe_ip(endpoint)
        mac = _canonical_mac(endpoint)
        if parsed_ip is not None:
            candidates = list(by_ip.get(str(parsed_ip), []))
            if len(candidates) == 1:
                asset_id = candidates[0]
                match_basis = "exact_ip"
            elif len(candidates) > 1:
                match_basis = "identity_conflict"
        elif mac:
            candidates = list(by_mac.get(mac, []))
            if len(candidates) == 1:
                asset_id = candidates[0]
                match_basis = "exact_mac"
            elif len(candidates) > 1:
                match_basis = "identity_conflict"

        classification = _classify_endpoint(
            endpoint,
            asset_id=asset_id,
            topology_segments=topology_segments,
        )
        row = {
            "id": _stable_id(ASSET_IDENTITY_RULE, endpoint, asset_id, match_basis),
            "rule_id": ASSET_IDENTITY_RULE,
            "endpoint": endpoint,
            "endpoint_kind": endpoint_kind.get(endpoint, "unknown"),
            "asset_id": asset_id,
            "match_basis": match_basis,
            "classification": classification,
            "confidence": "confirmed" if asset_id else "unknown",
        }
        if candidates and not asset_id:
            row["candidate_asset_ids"] = sorted(candidates)
            identity_conflicts.append(row)
        endpoint_identity.append(row)
        identity_by_endpoint[endpoint] = row
        if asset_id:
            observed_asset_ids.add(asset_id)

    normalized_conversations: list[dict[str, Any]] = []
    conversation_by_id: dict[str, dict[str, Any]] = {}
    conversations_by_asset: dict[str, list[dict[str, Any]]] = {}
    external_communications: list[dict[str, Any]] = []
    unclassified_communications: list[dict[str, Any]] = []

    for raw in graph_edges:
        if not isinstance(raw, dict):
            continue
        endpoint_a = _text(raw.get("endpoint_a"))
        endpoint_b = _text(raw.get("endpoint_b"))
        if not endpoint_a or not endpoint_b:
            continue
        conversation_id = _stable_id(
            "GA-CONVERSATION-001",
            min(endpoint_a, endpoint_b),
            max(endpoint_a, endpoint_b),
            raw.get("packets"),
            raw.get("bytes"),
        )
        item = {
            "id": conversation_id,
            "endpoint_a": endpoint_a,
            "endpoint_b": endpoint_b,
            "packets": int(raw.get("packets") or 0),
            "bytes": int(raw.get("bytes") or 0),
            "protocols": list(raw.get("protocols") or []),
            "ports": list(raw.get("ports") or []),
            "first_seen": raw.get("first_seen"),
            "last_seen": raw.get("last_seen"),
            "confidence": str(raw.get("confidence") or "observed"),
        }
        normalized_conversations.append(item)
        conversation_by_id[conversation_id] = item

        left = identity_by_endpoint.get(endpoint_a) or {}
        right = identity_by_endpoint.get(endpoint_b) or {}
        for identity in (left, right):
            asset_id = identity.get("asset_id")
            if asset_id:
                conversations_by_asset.setdefault(str(asset_id), []).append(item)

        external = _external_correlation(
            conversation=item,
            left=left,
            right=right,
        )
        if external is not None:
            external_communications.append(external)
        else:
            unclassified = _private_unknown_correlation(
                conversation=item,
                left=left,
                right=right,
            )
            if unclassified is not None:
                unclassified_communications.append(unclassified)

    service_usage: list[dict[str, Any]] = []
    observed_service_ids: set[str] = set()
    for service in sorted(
        services,
        key=lambda item: (str(item.get("asset_id") or ""), str(item.get("protocol") or ""), int(item.get("port") or 0), str(item.get("id") or "")),
    ):
        service_id = str(service.get("id") or "")
        asset_id = str(service.get("asset_id") or "")
        protocol = str(service.get("protocol") or "").lower()
        port = int(service.get("port") or 0)
        expected_port = f"{protocol}/{port}" if protocol and port else ""
        matches: list[str] = []
        if service_id and asset_id and expected_port:
            for conversation in conversations_by_asset.get(asset_id, []):
                tokens = {
                    str(row.get("port") or "").lower()
                    for row in conversation.get("ports") or []
                    if isinstance(row, dict)
                }
                if expected_port in tokens:
                    matches.append(str(conversation["id"]))
        observed = bool(matches)
        if observed:
            observed_service_ids.add(service_id)
        service_usage.append(
            {
                "id": _stable_id(SERVICE_USAGE_RULE, service_id, expected_port),
                "rule_id": SERVICE_USAGE_RULE,
                "service_id": service_id,
                "asset_id": asset_id,
                "protocol": protocol,
                "port": port,
                "state": service.get("state"),
                "observed_in_selected_traffic": observed,
                "match_basis": "observed_pair_destination_port" if observed else "not_observed",
                "confidence": "observed" if observed else "unknown",
                "conversation_ids": sorted(set(matches)),
            }
        )

    finding_relevance: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        asset_id = _text(finding.get("asset_id"))
        service_id = _text(finding.get("service_id"))
        if service_id and service_id in observed_service_ids:
            relevance = "service_traffic_observed"
            confidence = "observed"
        elif asset_id and asset_id in observed_asset_ids:
            relevance = "asset_traffic_observed"
            confidence = "observed"
        else:
            relevance = "uncorrelated"
            confidence = "unknown"
        finding_relevance.append(
            {
                "id": _stable_id(FINDING_RELEVANCE_RULE, finding_id, relevance),
                "rule_id": FINDING_RELEVANCE_RULE,
                "finding_id": finding_id,
                "asset_id": asset_id,
                "service_id": service_id,
                "severity": finding.get("severity"),
                "status": finding.get("status"),
                "traffic_relevance": relevance,
                "confidence": confidence,
            }
        )

    inventory_not_observed = [
        {
            "id": _stable_id(INVENTORY_COVERAGE_RULE, asset_id, "inventory_not_observed"),
            "rule_id": INVENTORY_COVERAGE_RULE,
            "asset_id": asset_id,
            "state": (asset_by_id.get(asset_id) or {}).get("state"),
            "addresses": list((asset_by_id.get(asset_id) or {}).get("addresses") or []),
            "meaning": "Asset exists in inventory but was not correlated with an endpoint visible in the selected capture.",
        }
        for asset_id in sorted(set(asset_by_id) - observed_asset_ids)
    ]
    unmatched_traffic = [
        row for row in endpoint_identity if row.get("asset_id") is None
    ]

    traffic_graph_available = isinstance(graph, dict) and isinstance(graph.get("edges"), list)
    topology_partial = bool(topology.get("partial"))
    partial = bool(source_truncated or topology_partial or not traffic_graph_available or identity_conflicts)
    warnings = list(source_warnings)
    if identity_conflicts:
        warnings.append("One or more traffic endpoints matched multiple inventory identities; no automatic merge was performed.")
    if not traffic_graph_available:
        warnings.append("Selected traffic analysis does not contain a usable communications graph.")
    warnings.append(
        "Service-use correlation in this schema is pair-level: traffic-analysis v1 stores destination ports aggregated per endpoint pair, so it does not prove which side owned the matched port."
    )
    warnings.append(
        "An inventory asset missing from the selected PCAP is not considered absent from the network; capture-point visibility is limited."
    )

    traffic_summary = traffic_analysis.get("summary") or {}
    topology_coverage = topology.get("coverage") if isinstance(topology.get("coverage"), dict) else {}
    return {
        "schema": "global-analysis",
        "schema_version": 1,
        "generated_at": _utc_now(),
        "deterministic": True,
        "network_io": False,
        "audit": dict(audit),
        "inputs": {
            "inventory_audit_id": audit.get("id"),
            "traffic_analysis_job_id": traffic_job.get("id"),
            "traffic_capture_audit_id": traffic_job.get("audit_id"),
            "traffic_result_reference": traffic_job.get("result_reference"),
            "traffic_analyzer_version": traffic_analysis.get("analyzer_version"),
            "topology_schema": topology.get("schema"),
            "topology_schema_version": topology.get("schema_version"),
        },
        "summary": {
            "inventory_assets": len(asset_by_id),
            "traffic_endpoints": len(endpoint_identity),
            "matched_traffic_endpoints": sum(1 for row in endpoint_identity if row.get("asset_id")),
            "unmatched_traffic_endpoints": len(unmatched_traffic),
            "inventory_assets_observed_in_traffic": len(observed_asset_ids),
            "inventory_assets_not_observed_in_traffic": len(inventory_not_observed),
            "services": len(service_usage),
            "services_observed_in_traffic": len(observed_service_ids),
            "external_communications": len(external_communications),
            "findings": len(finding_relevance),
            "partial": partial,
        },
        "asset_traffic_identity": endpoint_identity,
        "service_usage": service_usage,
        "finding_traffic_relevance": finding_relevance,
        "external_communications": external_communications,
        "unclassified_communications": unclassified_communications,
        "coverage": {
            "rule_id": INVENTORY_COVERAGE_RULE,
            "inventory_assets_not_observed": inventory_not_observed,
            "unmatched_traffic_endpoints": unmatched_traffic,
            "traffic_capture": {
                "frames": traffic_summary.get("frame_count", 0),
                "duration_seconds": traffic_summary.get("duration_seconds", 0),
                "conversations": len(normalized_conversations),
            },
            "topology": topology_coverage,
        },
        "source_health": {
            "inventory": "partial" if source_truncated else "sufficient",
            "traffic": "sufficient" if traffic_graph_available else "missing",
            "topology": "partial" if topology_partial else "sufficient",
            "identity": "partial" if identity_conflicts else "sufficient",
        },
        "partial": partial,
        "warnings": _unique(warnings),
    }


def _topology_networks(topology: dict[str, Any]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for segment in topology.get("segments") or []:
        if not isinstance(segment, dict):
            continue
        raw = _text(segment.get("network") or segment.get("label"))
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if network not in networks:
            networks.append(network)
    return networks


def _classify_endpoint(
    endpoint: str,
    *,
    asset_id: str | None,
    topology_segments: list[ipaddress._BaseNetwork],
) -> str:
    if asset_id:
        return "internal_asset"
    parsed = _safe_ip(endpoint)
    if parsed is None:
        return "unknown"
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local:
        return "special"
    if str(parsed) == "255.255.255.255":
        return "special"
    for network in topology_segments:
        if parsed.version == network.version and parsed in network:
            return "internal_segment"
    if parsed.is_global:
        return "external_global"
    if parsed.is_private:
        return "private_unknown"
    return "unknown"


def _external_correlation(
    *,
    conversation: dict[str, Any],
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any] | None:
    pairs = ((left, right), (right, left))
    for internal, external in pairs:
        asset_id = internal.get("asset_id")
        if not asset_id or external.get("classification") != "external_global":
            continue
        endpoint = str(external.get("endpoint") or "")
        return {
            "id": _stable_id(EXTERNAL_COMMUNICATION_RULE, conversation.get("id"), asset_id, endpoint),
            "rule_id": EXTERNAL_COMMUNICATION_RULE,
            "asset_id": asset_id,
            "external_endpoint": endpoint,
            "conversation_id": conversation.get("id"),
            "packets": conversation.get("packets", 0),
            "bytes": conversation.get("bytes", 0),
            "protocols": list(conversation.get("protocols") or []),
            "ports": list(conversation.get("ports") or []),
            "confidence": "observed",
        }
    return None


def _private_unknown_correlation(
    *,
    conversation: dict[str, Any],
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any] | None:
    pairs = ((left, right), (right, left))
    for internal, unknown in pairs:
        asset_id = internal.get("asset_id")
        if not asset_id or unknown.get("classification") != "private_unknown":
            continue
        return {
            "id": _stable_id("GA-PRIVATE-UNKNOWN-001", conversation.get("id"), asset_id, unknown.get("endpoint")),
            "rule_id": "GA-PRIVATE-UNKNOWN-001",
            "asset_id": asset_id,
            "endpoint": unknown.get("endpoint"),
            "conversation_id": conversation.get("id"),
            "reason": "Private endpoint is outside known topology segments and was not matched to inventory; it is not classified as external.",
            "confidence": "unknown",
        }
    return None


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result
