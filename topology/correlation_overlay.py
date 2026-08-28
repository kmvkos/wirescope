"""Attach explainable PCAP↔inventory correlation to topology overlay."""

from __future__ import annotations

from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from traffic_analysis.correlation_v2 import correlate_inventory_with_pcap


class CorrelationOverlaySourceError(RuntimeError):
    pass


def _load_document(services, job_id: str) -> dict[str, Any]:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise CorrelationOverlaySourceError(f"Traffic analysis not found: {job_id}") from exc
    if job.type != "traffic_analysis" or job.status != JobStatus.COMPLETED or not job.result_reference:
        raise CorrelationOverlaySourceError("Traffic analysis is not completed")
    try:
        artifact = services.jobs.artifact(job.result_reference)
        document = services.evidence.read_json(artifact)
    except (EntityNotFound, JobExecutionError) as exc:
        raise CorrelationOverlaySourceError("Traffic analysis result could not be loaded") from exc
    return document if isinstance(document, dict) else {}


def _assets(services, audit_id: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = services.inventory.list_assets(
            audit_id=audit_id,
            limit=500,
            offset=offset,
            include_services=False,
        )
        for asset in page.items:
            result.append(
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
    return result


def decorate_correlation_v2(
    services,
    audit_id: str,
    topology: dict[str, Any],
    *,
    traffic_analysis_job_id: str | None,
) -> dict[str, Any]:
    if not traffic_analysis_job_id or not topology.get("overlay"):
        return topology
    overlay = dict(topology.get("overlay") or {})
    compatibility = overlay.get("compatibility")
    if not isinstance(compatibility, dict):
        return topology

    document = _load_document(services, traffic_analysis_job_id)
    correlation = correlate_inventory_with_pcap(
        assets=_assets(services, audit_id),
        traffic_document=document,
        compatibility=compatibility,
    )
    overlay["correlation"] = correlation
    topology["overlay"] = overlay
    return topology


__all__ = ["CorrelationOverlaySourceError", "decorate_correlation_v2"]
