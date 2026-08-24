from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.capabilities import capability_inventory
from backend.correlations import correlation_summary
from backend.dependencies import AppServices, get_services
from backend.insights import audit_diff, dashboard
from engine.active_profiles import ProfileConfigError, profile_catalog
from findings.store import FindingNotFound
from jobs.errors import JobExecutionError
from jobs.service import EntityNotFound


router = APIRouter()


def _missing(message: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "not_found", "message": message},
    )


@router.get("/capabilities")
def capabilities(services: AppServices = Depends(get_services)) -> dict:
    return capability_inventory(services.settings)


@router.get("/scan-profiles")
def scan_profiles(services: AppServices = Depends(get_services)) -> dict:
    try:
        return {"profiles": profile_catalog(services.settings)}
    except ProfileConfigError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "profile_config_error", "message": str(exc)},
        ) from exc


@router.get("/audits/{audit_id}/dashboard")
def audit_dashboard(
    audit_id: str,
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return dashboard(services, audit_id)
    except EntityNotFound as exc:
        raise _missing(str(exc)) from exc


@router.get("/audits/{audit_id}/correlations")
def audit_correlations(
    audit_id: str,
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        services.jobs.get_audit(audit_id)
        return correlation_summary(services.inventory, audit_id)
    except EntityNotFound as exc:
        raise _missing(str(exc)) from exc


@router.get("/audits/{audit_id}/diff")
def compare_audits(
    audit_id: str,
    against: str = Query(min_length=1, max_length=64),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return audit_diff(services, against, audit_id)
    except EntityNotFound as exc:
        raise _missing(str(exc)) from exc


@router.get("/audits/{audit_id}/findings/{finding_id}/evidence")
def finding_evidence(
    audit_id: str,
    finding_id: str,
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        finding = services.findings.get_finding(
            audit_id=audit_id,
            finding_id=finding_id,
            include_events=False,
        )
    except FindingNotFound as exc:
        raise _missing(str(exc)) from exc

    items = []
    for artifact_id in finding.evidence_artifact_ids:
        try:
            artifact = services.jobs.artifact(artifact_id)
        except EntityNotFound:
            items.append({"id": artifact_id, "available": False})
            continue
        if artifact.audit_id != audit_id:
            continue
        items.append(
            {
                "id": artifact.id,
                "available": True,
                "artifact_type": artifact.artifact_type,
                "content_type": artifact.content_type,
                "size": artifact.size,
                "sha256": artifact.sha256,
                "created_at": artifact.created_at,
                "url": f"/api/v1/audits/{audit_id}/artifacts/{artifact.id}",
            }
        )
    return {"finding_id": finding_id, "items": items}


@router.get("/audits/{audit_id}/artifacts/{artifact_id}")
def artifact_content(
    audit_id: str,
    artifact_id: str,
    services: AppServices = Depends(get_services),
) -> Response:
    try:
        services.jobs.get_audit(audit_id)
        artifact = services.jobs.artifact(artifact_id)
        if artifact.audit_id != audit_id:
            raise _missing(f"Artifact not found in audit: {artifact_id}")
        payload = services.evidence.read_bytes(artifact)
    except EntityNotFound as exc:
        raise _missing(str(exc)) from exc
    except JobExecutionError as exc:
        raise HTTPException(
            status_code=503,
            detail=exc.error.model_dump(mode="json"),
        ) from exc

    content_type = artifact.content_type or "application/octet-stream"
    text_like = (
        content_type.startswith("text/")
        or content_type in {
            "application/json",
            "application/xml",
            "application/x-ndjson",
        }
    )
    disposition = "inline" if text_like else "attachment"
    return Response(
        content=payload,
        media_type=content_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{artifact.id}"',
            "X-WireScope-SHA256": artifact.sha256,
        },
    )
