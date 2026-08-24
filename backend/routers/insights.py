from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.capabilities import capability_inventory
from backend.dependencies import AppServices, get_services
from backend.insights import audit_diff, dashboard
from findings.store import FindingNotFound
from jobs.errors import JobExecutionError
from jobs.service import EntityNotFound


router = APIRouter()


@router.get("/capabilities")
def capabilities(services: AppServices = Depends(get_services)) -> dict:
    return capability_inventory(services.settings)


@router.get("/audits/{audit_id}/dashboard")
def audit_dashboard(
    audit_id: str,
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return dashboard(services, audit_id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": str(exc)}) from exc


@router.get("/audits/{audit_id}/diff")
def compare_audits(
    audit_id: str,
    against: str = Query(min_length=1, max_length=64),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return audit_diff(services, against, audit_id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": str(exc)}) from exc


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
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": str(exc)}) from exc

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
                "url": f"/api/v1/artifacts/{artifact.id}",
            }
        )
    return {"finding_id": finding_id, "items": items}


@router.get("/artifacts/{artifact_id}")
def artifact_content(
    artifact_id: str,
    services: AppServices = Depends(get_services),
) -> Response:
    try:
        artifact = services.jobs.artifact(artifact_id)
        payload = services.evidence.read_bytes(artifact)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": str(exc)}) from exc
    except JobExecutionError as exc:
        raise HTTPException(status_code=503, detail=exc.error.model_dump(mode="json")) from exc

    text_like = (
        artifact.content_type.startswith("text/")
        or artifact.content_type in {
            "application/json",
            "application/xml",
            "application/x-ndjson",
        }
    )
    disposition = "inline" if text_like else "attachment"
    return Response(
        content=payload,
        media_type=artifact.content_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{artifact.id}"',
            "X-WireScope-SHA256": artifact.sha256,
        },
    )
