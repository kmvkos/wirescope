"""Milestone-12 safety/enrichment layer for a selected traffic overlay.

Legacy code still materializes retained communications for compatibility. This
module adds the semantics that raw communication lacks: observation-domain
compatibility, conservative PCAP↔inventory identity, endpoint state and strong
CDP/LLDP/MNDP discovery identity.
"""

from __future__ import annotations

from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from traffic_analysis.domain import assess_observation_domain


class TrafficOverlaySourceError(RuntimeError):
    pass


def _merge_unique(current: list[Any], incoming: list[Any]) -> list[Any]:
    result = list(current)
    for item in incoming:
        if item not in result:
            result.append(item)
    return result


def _bare(value: Any) -> str:
    return str(value or "").split("/", 1)[0].strip()


def _mac(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    parts = text.split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return None
    if text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or octets[0] & 0x01:
        return None
    return text


def _load_document(services, job_id: str) -> dict[str, Any]:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise TrafficOverlaySourceError(f"Traffic analysis not found: {job_id}") from exc
    if job.type != "traffic_analysis":
        raise TrafficOverlaySourceError("Selected overlay is not a traffic analysis job")
    if job.status != JobStatus.COMPLETED or not job.result_reference:
        raise TrafficOverlaySourceError("Selected traffic analysis is not completed")
    try:
        artifact = services.jobs.artifact(job.result_reference)
        if artifact.job_id != job.id or artifact.artifact_type != "traffic_analysis_result":
            raise TrafficOverlaySourceError("Traffic analysis result reference is inconsistent")
        document = services.evidence.read_json(artifact)
    except EntityNotFound as exc:
        raise TrafficOverlaySourceError("Traffic analysis result artifact was not found") from exc
    except JobExecutionError as exc:
        raise TrafficOverlaySourceError("Traffic analysis result could not be read") from exc
    if not isinstance(document, dict):
        raise TrafficOverlaySourceError("Traffic analysis result is not an object")
    return document


def _inventory_assets(services, audit_id: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = services.inventory.list_assets(
            audit_id=audit_id,
            limit=500,
            offset=offset,
            include_services=False,
        )
        for asset in page.items:
            items.append(
                {
                    "id": asset.id,
                    "mac": asset.mac,
                    "addresses": [item.address for item in asset.addresses],
                    "names": [item.name for item in asset.names],
                }
            )
        offset += len(page.items)
        if not page.items or offset >= page.total:
            break
    return items


def _correlation_summary(
    *,
    compatibility: dict[str, Any],
    assets: list[dict[str, Any]],
    document: dict[str, Any],
) -> dict[str, Any]:
    matches = compatibility.get("matches") or {}
    exact_ips = list(matches.get("exact_ips") or [])
    exact_macs = list(matches.get("exact_macs") or [])
    status = str(compatibility.get("status") or "insufficient_evidence")

    if status == "different_domain":
        result_status = "skipped_different_domain"
        headline = (
            "Прямая asset correlation не выполняется: PCAP и аудит относятся к разным observation domains."
        )
    elif exact_ips or exact_macs:
        result_status = "matched"
        headline = f"Есть прямые identity совпадения: MAC={len(exact_macs)}, IP={len(exact_ips)}."
    elif status == "compatible":
        result_status = "compatible_without_exact_identity"
        headline = "PCAP совместим со scope аудита, но точных inventory identity совпадений пока нет."
    elif status == "partial":
        result_status = "partial"
        headline = (
            "Источники частично совместимы; structural enrichment отключён до статуса compatible."
        )
    else:
        result_status = "insufficient_evidence"
        headline = (
            "Недостаточно evidence для надёжной PCAP↔inventory correlation; structural enrichment отключён."
        )

    resolution = document.get("identity_resolution") or {}
    return {
        "schema": "pcap-inventory-correlation-summary",
        "schema_version": 1,
        "status": result_status,
        "headline": headline,
        "inventory_asset_count": len(assets),
        "pcap_identity_candidate_count": int(resolution.get("candidate_count") or 0),
        "pcap_resolved_identity_count": int(resolution.get("resolved_count") or 0),
        "exact_ip_matches": exact_ips,
        "exact_mac_matches": exact_macs,
        "ip_mac_conflicts": list(matches.get("ip_mac_conflicts") or []),
        "zero_match_is_failure": False if status == "different_domain" else None,
    }


def _enrichment_policy(compatibility: dict[str, Any]) -> tuple[bool, str, str | None]:
    status = str(compatibility.get("status") or "insufficient_evidence")
    if status == "compatible":
        return True, "allowed", None
    if status == "different_domain":
        return False, "skipped_different_domain", "different_observation_domain"
    if status == "partial":
        return False, "skipped_unconfirmed_domain", "partial_observation_domain"
    return False, "skipped_unconfirmed_domain", "insufficient_observation_domain"


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


def _candidate_conflicts_with_node(node: dict[str, Any], candidate: dict[str, Any]) -> bool:
    node_mac = _mac(node.get("mac"))
    candidate_mac = _mac(candidate.get("mac"))
    return bool(node_mac and candidate_mac and node_mac != candidate_mac)


def _annotate_endpoint_states(topology: dict[str, Any], document: dict[str, Any]) -> None:
    state_by_endpoint = {
        str(item.get("endpoint")): str(item.get("state"))
        for item in document.get("endpoint_evidence") or []
        if isinstance(item, dict) and item.get("endpoint") and item.get("state")
    }
    candidate_by_address: dict[str, dict[str, Any]] = {}
    candidate_by_mac: dict[str, dict[str, Any]] = {}
    for candidate in (document.get("identity_resolution") or {}).get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        for address in candidate.get("addresses") or []:
            candidate_by_address[_bare(address)] = candidate
        parsed_mac = _mac(candidate.get("mac"))
        if parsed_mac:
            candidate_by_mac[parsed_mac] = candidate

    for node in topology.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        addresses = [_bare(value) for value in node.get("addresses") or [] if _bare(value)]

        candidate = None
        for address in addresses:
            if address in candidate_by_address:
                candidate = candidate_by_address[address]
                break
        if candidate is None:
            parsed_node_mac = _mac(node.get("mac"))
            if parsed_node_mac:
                candidate = candidate_by_mac.get(parsed_node_mac)

        identity_conflict = bool(
            candidate is not None and _candidate_conflicts_with_node(node, candidate)
        )
        states = [state_by_endpoint[address] for address in addresses if address in state_by_endpoint]
        if states and not identity_conflict:
            priority = ["confirmed_responder", "observed_sender", "external_peer", "observed_peer", "probed_target"]
            node["pcap_state"] = next((state for state in priority if state in states), states[0])

        if candidate is not None and not identity_conflict:
            node["pcap_local_identity"] = True
            node["pcap_identity_status"] = candidate.get("status")
            node["pcap_identity_confidence"] = candidate.get("confidence")
            node["provenance"] = _merge_unique(node.get("provenance") or [], ["pcap-identity"])


def _enrich_discovery_devices(topology: dict[str, Any], document: dict[str, Any], job_id: str) -> int:
    discovery = document.get("discovery_evidence") or {}
    devices = discovery.get("devices") or []
    if not isinstance(devices, list):
        return 0

    aliases = _aliases(topology)
    added = 0
    for index, device in enumerate(devices, start=1):
        if not isinstance(device, dict):
            continue
        source_mac = _mac(device.get("source_mac"))
        identifiers: list[str] = []
        if source_mac:
            identifiers.append(source_mac)
        identifiers.extend(_bare(value).lower() for value in device.get("addresses") or [] if _bare(value))
        identifiers.extend(str(value).strip().lower() for value in device.get("names") or [] if str(value).strip())
        node = next((aliases.get(value) for value in identifiers if aliases.get(value)), None)

        # Reused RFC1918 addresses and names are not enough to merge a PCAP
        # discovery device into an inventory node when both sides know different
        # unicast MACs. Preserve them as separate identities instead.
        if node is not None and source_mac:
            node_mac = _mac(node.get("mac"))
            if node_mac and node_mac != source_mac:
                node = None

        protocol = str(device.get("protocol") or "discovery").lower()
        names = [str(value) for value in device.get("names") or [] if value]
        addresses = [_bare(value) for value in device.get("addresses") or [] if _bare(value)]
        label = (
            (names[0] if names else None)
            or (addresses[0] if addresses else None)
            or source_mac
            or f"{protocol.upper()} device"
        )
        if node is None:
            node = {
                "id": f"pcap-device:{job_id[:8]}:{protocol}:{index}",
                "kind": "network-device",
                "label": label,
                "roles": [],
                "addresses": [],
                "names": [],
                "provenance": [],
                "confidence": "confirmed",
                "pcap_only": True,
            }
            topology.setdefault("nodes", []).append(node)
            added += 1

        node["kind"] = "network-device"
        node["label"] = names[0] if names else node.get("label") or label
        node["roles"] = _merge_unique(
            node.get("roles") or [],
            ["network-device", *[str(role) for role in device.get("roles") or []]],
        )
        node["addresses"] = _merge_unique(node.get("addresses") or [], addresses)
        node["names"] = _merge_unique(node.get("names") or [], names)
        node["provenance"] = _merge_unique(node.get("provenance") or [], [protocol, "pcap-discovery"])
        node["confidence"] = "confirmed"
        node["pcap_local_identity"] = True
        node["pcap_discovery"] = True
        if source_mac:
            node["mac"] = node.get("mac") or source_mac
        for key in ("platform", "software", "port_id", "port_description", "native_vlan"):
            if device.get(key) not in {None, ""}:
                node[key] = device.get(key)

        for value in [node.get("mac"), node.get("label"), *node.get("addresses", []), *node.get("names", [])]:
            alias = _bare(value).lower()
            if alias:
                aliases[alias] = node
    return added


def decorate_traffic_overlay(
    services,
    audit_id: str,
    topology: dict[str, Any],
    *,
    traffic_analysis_job_id: str | None,
) -> dict[str, Any]:
    """Attach compatibility/correlation and enrich strong PCAP identity."""
    if not traffic_analysis_job_id or not topology.get("overlay"):
        return topology

    document = _load_document(services, traffic_analysis_job_id)
    assets = _inventory_assets(services, audit_id)
    latest_scope = services.inventory.latest_scope(audit_id)
    confirmed_scope = latest_scope.model_dump(mode="json") if latest_scope else None
    audit = services.jobs.get_audit(audit_id)

    compatibility = assess_observation_domain(
        assets=assets,
        confirmed_scope=confirmed_scope,
        audit_scope=dict(audit.scope or {}),
        audit_interface=audit.interface,
        traffic_document=document,
    )
    correlation = _correlation_summary(
        compatibility=compatibility,
        assets=assets,
        document=document,
    )

    enrichment_allowed, enrichment_status, enrichment_reason = _enrichment_policy(
        compatibility
    )
    discovery_nodes_added = 0
    endpoint_annotation_applied = False
    if enrichment_allowed:
        _annotate_endpoint_states(topology, document)
        endpoint_annotation_applied = True
        discovery_nodes_added = _enrich_discovery_devices(
            topology,
            document,
            traffic_analysis_job_id,
        )

    overlay = dict(topology.get("overlay") or {})
    overlay["compatibility"] = compatibility
    overlay["correlation"] = correlation
    overlay["topology_enrichment"] = {
        "allowed": enrichment_allowed,
        "status": enrichment_status,
        "reason": enrichment_reason,
        "endpoint_annotation_applied": endpoint_annotation_applied,
        "discovery_nodes_added": discovery_nodes_added,
    }
    overlay["identity_resolution"] = {
        key: value
        for key, value in (document.get("identity_resolution") or {}).items()
        if key in {"candidate_count", "resolved_count", "provisional_count", "conflict_count"}
    }
    overlay["discovery"] = {
        "status": (document.get("discovery_evidence_status") or {}).get("status"),
        "device_count": len((document.get("discovery_evidence") or {}).get("devices") or []),
        "cdp_devices": len(((document.get("discovery_evidence") or {}).get("cdp") or {}).get("devices") or []),
        "lldp_devices": len(((document.get("discovery_evidence") or {}).get("lldp") or {}).get("devices") or []),
        "mndp_devices": len(((document.get("discovery_evidence") or {}).get("mndp") or {}).get("devices") or []),
        "topology_nodes_added": discovery_nodes_added,
        "topology_enrichment_skipped": not enrichment_allowed,
        "topology_enrichment_skip_reason": enrichment_reason,
    }
    topology["overlay"] = overlay

    if not enrichment_allowed:
        status = str(compatibility.get("status") or "insufficient_evidence")
        if status == "different_domain":
            warning = (
                "Выбранный PCAP относится к другому observation domain. Traffic evidence сохранён отдельно, "
                "но отсутствие прямых совпадений с inventory не считается ошибкой корреляции."
            )
        else:
            warning = (
                f"Observation domain выбранного PCAP имеет статус {status}; structural enrichment пропущён "
                "до подтверждения compatible. Raw Traffic/Evidence сохранены отдельно."
            )
        warnings = list(topology.get("warnings") or [])
        if warning not in warnings:
            warnings.append(warning)
        topology["warnings"] = warnings

    return topology


__all__ = ["TrafficOverlaySourceError", "decorate_traffic_overlay"]
