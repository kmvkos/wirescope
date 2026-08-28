"""Milestone-12 safety layer for an explicitly selected traffic overlay.

The legacy builder still materializes the retained communications graph so old
exports remain compatible. This decorator adds the missing semantic guardrail:
before UI/correlation uses that graph, it determines whether the audit inventory
and selected PCAP plausibly describe the same observation domain.
"""

from __future__ import annotations

from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from traffic_analysis.domain import assess_observation_domain


class TrafficOverlaySourceError(RuntimeError):
    pass


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
        headline = (
            f"Есть прямые identity совпадения: MAC={len(exact_macs)}, IP={len(exact_ips)}."
        )
    elif status == "compatible":
        result_status = "compatible_without_exact_identity"
        headline = (
            "PCAP совместим со scope аудита, но точных inventory identity совпадений пока нет."
        )
    elif status == "partial":
        result_status = "partial"
        headline = "Источники частично совместимы; автоматические merge должны оставаться консервативными."
    else:
        result_status = "insufficient_evidence"
        headline = "Недостаточно evidence для надёжной PCAP↔inventory correlation."

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
        "zero_match_is_failure": False if status == "different_domain" else None,
    }


def decorate_traffic_overlay(
    services,
    audit_id: str,
    topology: dict[str, Any],
    *,
    traffic_analysis_job_id: str | None,
) -> dict[str, Any]:
    """Attach domain/correlation semantics before presentation projections."""
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

    overlay = dict(topology.get("overlay") or {})
    overlay["compatibility"] = compatibility
    overlay["correlation"] = correlation
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
    }
    topology["overlay"] = overlay

    if compatibility.get("status") == "different_domain":
        warning = (
            "Выбранный PCAP относится к другому observation domain. Traffic evidence сохранён отдельно, "
            "но отсутствие прямых совпадений с inventory не считается ошибкой корреляции."
        )
        warnings = list(topology.get("warnings") or [])
        if warning not in warnings:
            warnings.append(warning)
        topology["warnings"] = warnings

    return topology


__all__ = ["TrafficOverlaySourceError", "decorate_traffic_overlay"]
