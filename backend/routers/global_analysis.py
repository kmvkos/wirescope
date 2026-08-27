from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from backend.dependencies import AppServices, get_services
from backend.models import JobAcceptedResponse
from global_analysis import GlobalAnalysisSourceError, build_global_analysis
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition


router = APIRouter()


class GlobalAnalysisJobRequest(BaseModel):
    traffic_analysis_job_id: str = Field(min_length=1)
    priority: int = Field(default=0, ge=-100, le=100)


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

    try:
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="global_analysis",
            target=audit.interface,
            parameters={
                "traffic_analysis_job_id": traffic_job.id,
                "actor": request.state.user.username,
            },
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
