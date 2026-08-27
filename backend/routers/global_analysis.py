from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from backend.dependencies import AppServices, get_services
from backend.models import JobAcceptedResponse
from global_analysis import GlobalAnalysisSourceError, build_global_analysis
from global_analysis.render import render_markdown, render_text
from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition
from persistence.models import JobModel


router = APIRouter()


class GlobalAnalysisJobRequest(BaseModel):
    traffic_analysis_job_id: str = Field(min_length=1)
    rebuild_of_job_id: str | None = Field(default=None, min_length=1)
    priority: int = Field(default=0, ge=-100, le=100)


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _global_analysis_artifact(job_id: str, services: AppServices):
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Global analysis job not found"},
        ) from exc
    if job.type != "global_analysis":
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Global analysis job not found"},
        )
    if job.status is not JobStatus.COMPLETED or not job.result_reference:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_unavailable",
                "message": "Global analysis result is not completed",
            },
        )
    try:
        artifact = services.jobs.artifact(job.result_reference)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_reference_missing",
                "message": "Global analysis result artifact was not found",
            },
        ) from exc
    if (
        artifact.job_id != job.id
        or artifact.audit_id != job.audit_id
        or artifact.artifact_type != "global_analysis_result"
        or artifact.schema_name != "global-analysis"
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_reference_mismatch",
                "message": "Global analysis result does not belong to this job",
            },
        )
    return job, artifact


def _global_analysis_document(job_id: str, services: AppServices):
    job, artifact = _global_analysis_artifact(job_id, services)
    try:
        document = services.evidence.read_json(artifact)
    except JobExecutionError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_unreadable",
                "message": "Global analysis result could not be read",
            },
        ) from exc
    if not isinstance(document, dict) or document.get("schema") != "global-analysis":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_contract_invalid",
                "message": "Stored global analysis has an unsupported contract",
            },
        )
    return job, artifact, document


@router.get("/audits/{audit_id}/global-analysis")
def audit_global_analysis(
    audit_id: str,
    traffic_analysis_job_id: str = Query(min_length=1),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return build_global_analysis(
            services,
            audit_id,
            traffic_analysis_job_id=traffic_analysis_job_id,
        )
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    except GlobalAnalysisSourceError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "global_analysis_source_invalid", "message": str(exc)},
        ) from exc


@router.get("/audits/{audit_id}/global-analysis/history")
def global_analysis_history(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc

    with services.database.session() as session:
        rows = session.scalars(
            select(JobModel)
            .where(
                JobModel.audit_id == audit_id,
                JobModel.type == "global_analysis",
            )
            .order_by(JobModel.created_at.desc(), JobModel.id.desc())
            .limit(limit)
        ).all()

    items: list[dict] = []
    for row in rows:
        parameters = dict(row.parameters or {})
        item = {
            "job_id": row.id,
            "audit_id": row.audit_id,
            "status": row.status,
            "progress": int(row.progress or 0),
            "stage": row.stage,
            "message": row.message,
            "created_at": _iso_utc(row.created_at),
            "started_at": _iso_utc(row.started_at),
            "finished_at": _iso_utc(row.finished_at),
            "traffic_analysis_job_id": parameters.get("traffic_analysis_job_id"),
            "rebuild_of_job_id": parameters.get("rebuild_of_job_id"),
            "result_reference": row.result_reference,
            "result_available": False,
            "partial": None,
            "generated_at": None,
            "summary": None,
            "error": None,
        }
        if row.error_code or row.error_message:
            item["error"] = {
                "code": row.error_code,
                "category": row.error_category,
                "message": row.error_message,
                "component": row.error_component,
                "retryable": bool(row.error_retryable),
            }
        if row.result_reference and row.status == JobStatus.COMPLETED.value:
            try:
                artifact = services.jobs.artifact(row.result_reference)
                if (
                    artifact.job_id == row.id
                    and artifact.audit_id == audit_id
                    and artifact.artifact_type == "global_analysis_result"
                ):
                    document = services.evidence.read_json(artifact)
                    if isinstance(document, dict) and document.get("schema") == "global-analysis":
                        item["result_available"] = True
                        item["partial"] = bool(document.get("partial"))
                        item["generated_at"] = document.get("generated_at")
                        item["summary"] = dict(document.get("summary") or {})
            except (EntityNotFound, JobExecutionError):
                pass
        items.append(item)
    return {"items": items, "total": len(items)}


@router.get("/jobs/{job_id}/global-analysis")
def get_global_analysis(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> dict:
    _job, _artifact, document = _global_analysis_document(job_id, services)
    return document


@router.get("/jobs/{job_id}/global-analysis/export")
def export_global_analysis(
    job_id: str,
    format: str = Query(default="json"),
    services: AppServices = Depends(get_services),
) -> Response:
    requested = format.strip().lower()
    if requested == "txt":
        requested = "text"
    if requested == "md":
        requested = "markdown"
    if requested not in {"json", "text", "markdown"}:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "unsupported_global_analysis_format",
                "message": "format must be json, text, or markdown",
            },
        )

    job, artifact, document = _global_analysis_document(job_id, services)
    if requested == "json":
        try:
            payload = services.evidence.read_bytes(artifact)
        except JobExecutionError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "global_analysis_unreadable",
                    "message": "Global analysis result could not be read",
                },
            ) from exc
        media_type = "application/json"
        extension = "json"
    elif requested == "text":
        payload = render_text(document).encode("utf-8")
        media_type = "text/plain; charset=utf-8"
        extension = "txt"
    else:
        payload = render_markdown(document).encode("utf-8")
        media_type = "text/markdown; charset=utf-8"
        extension = "md"

    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="wirescope-global-analysis-{job.id[:8]}.{extension}"'
            )
        },
    )


@router.post(
    "/audits/{audit_id}/global-analysis",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_global_analysis(
    audit_id: str,
    payload: GlobalAnalysisJobRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        traffic_job = services.jobs.get_job(payload.traffic_analysis_job_id)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc

    if (
        traffic_job.type != "traffic_analysis"
        or traffic_job.status is not JobStatus.COMPLETED
        or not traffic_job.result_reference
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_analysis_source_invalid",
                "message": "Selected traffic analysis must be a completed job with a persisted result",
            },
        )

    rebuild_of_job_id = payload.rebuild_of_job_id
    if rebuild_of_job_id:
        try:
            previous = services.jobs.get_job(rebuild_of_job_id)
        except EntityNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail={"code": "not_found", "message": "Previous global analysis job not found"},
            ) from exc
        previous_parameters = dict(previous.parameters or {})
        if previous.type != "global_analysis" or previous.audit_id != audit.id:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "invalid_global_analysis_rebuild_source",
                    "message": "Rebuild source must be a global analysis job from the same audit",
                },
            )
        previous_traffic = str(previous_parameters.get("traffic_analysis_job_id") or "")
        if previous_traffic and previous_traffic != traffic_job.id:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "global_analysis_rebuild_input_mismatch",
                    "message": "Rebuild must use the same selected traffic analysis as the previous result",
                },
            )

    parameters = {
        "traffic_analysis_job_id": traffic_job.id,
        "actor": request.state.user.username,
    }
    if rebuild_of_job_id:
        parameters["rebuild_of_job_id"] = rebuild_of_job_id

    try:
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="global_analysis",
            target=audit.interface,
            parameters=parameters,
            priority=payload.priority,
            resource_key=f"audit:{audit.id}:global_analysis",
            resource_group="global_analysis",
            resource_limit=1,
        )
    except InvalidTransition as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_transition", "message": str(exc)},
        ) from exc

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/v1/jobs/{job.id}",
    )
