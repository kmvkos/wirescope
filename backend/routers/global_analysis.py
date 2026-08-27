from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import AppServices, get_services
from global_analysis import GlobalAnalysisSourceError, build_global_analysis
from jobs.service import EntityNotFound


router = APIRouter()


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
