from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import AppServices, get_services
from jobs.service import EntityNotFound
from topology import TopologySourceError, build_global_topology, build_topology


router = APIRouter()


@router.get("/topology/global")
def global_topology(
    limit: int = Query(default=100, ge=1, le=100),
    services: AppServices = Depends(get_services),
) -> dict:
    return build_global_topology(services, limit=limit)


@router.get("/audits/{audit_id}/topology")
def audit_topology(
    audit_id: str,
    traffic_analysis_job_id: str | None = Query(default=None),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return build_topology(
            services,
            audit_id,
            traffic_analysis_job_id=traffic_analysis_job_id,
        )
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    except TopologySourceError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "topology_source_invalid", "message": str(exc)},
        ) from exc
