from __future__ import annotations

import json
import platform
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel

from auth.models import Role
from backend.capabilities import capability_inventory
from backend.dependencies import AppServices, get_services
from backend.lifecycle import LifecycleService
from backend.recovery import RecoveryService, RetryNotAllowed
from jobs.service import EntityNotFound
from persistence.schema import migrations_current


router = APIRouter()


class CleanupRequest(BaseModel):
    confirm: bool = False
    include_raw: bool = False


def _require_auditor(request: Request) -> None:
    user = getattr(request.state, "user", None)
    if user is None or user.role is not Role.AUDITOR:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "forbidden_role",
                "message": "Auditor role required",
            },
        )


def _lifecycle(services: AppServices) -> LifecycleService:
    return LifecycleService(services.database, services.evidence, services.settings)


@router.get("/audit-log")
def audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: str | None = Query(default=None, max_length=128),
    action: str | None = Query(default=None, max_length=64),
    audit_id: str | None = Query(default=None, max_length=64),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    _require_auditor(request)
    return services.audit_log.list_events(
        limit=limit,
        offset=offset,
        actor=actor,
        action=action,
        audit_id=audit_id,
    )


@router.get("/maintenance/status")
def maintenance_status(
    request: Request,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    _require_auditor(request)
    return _lifecycle(services).status()


@router.post("/maintenance/cleanup")
def maintenance_cleanup(
    payload: CleanupRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    _require_auditor(request)
    return _lifecycle(services).cleanup(
        confirm=payload.confirm,
        include_raw=payload.include_raw,
    )


@router.post("/jobs/{job_id}/retry", status_code=202)
def retry_job(
    job_id: str,
    request: Request,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    _require_auditor(request)
    recovery = RecoveryService(services.database, services.jobs)
    try:
        job = recovery.retry(job_id, actor=request.state.user.username)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    except RetryNotAllowed as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "retry_not_allowed", "message": str(exc)},
        ) from exc
    return {
        "audit_id": job.audit_id,
        "job_id": job.id,
        "retry_of": job_id,
        "status": job.status.value,
        "status_url": f"/api/v1/jobs/{job.id}",
    }


def _diagnostic_payload(services: AppServices) -> dict[str, Any]:
    lifecycle = _lifecycle(services)
    capabilities = capability_inventory(services.settings)
    database_ready = services.database.is_accessible()
    migrations_ready = database_ready and migrations_current(
        services.database,
        services.settings.project_root,
    )
    worker_ready = migrations_ready and services.jobs.worker_is_ready(
        services.settings.worker_stale_after_seconds
    )
    lifecycle_status = lifecycle.status()
    free_bytes = lifecycle_status["storage"]["filesystem_free_bytes"]
    runtime_checks = {
        "database": database_ready,
        "migrations": migrations_ready,
        "database_quick_check": (
            lifecycle_status["database"]["quick_check"] == "ok"
        ),
        "worker": worker_ready,
        "core_tools": bool(capabilities["core_ready"]),
        "disk_space": free_bytes >= 256 * 1024 * 1024,
    }
    return {
        "schema": "wirescope-diagnostics",
        "schema_version": 1,
        "product": services.settings.app_name,
        "version": services.settings.app_version,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "listener": capabilities["web"],
        "runtime": {
            "ready": all(runtime_checks.values()),
            "checks": runtime_checks,
        },
        "capabilities": capabilities,
        "lifecycle": lifecycle_status,
        "audit_log": services.audit_log.summary(limit=20),
    }


@router.get("/diagnostics")
def diagnostics(
    request: Request,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    _require_auditor(request)
    return _diagnostic_payload(services)


@router.get("/diagnostics/export")
def diagnostics_export(
    request: Request,
    services: AppServices = Depends(get_services),
) -> Response:
    _require_auditor(request)
    payload = json.dumps(
        _diagnostic_payload(services),
        ensure_ascii=False,
        indent=2,
        default=str,
    ).encode("utf-8")
    return Response(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="wirescope-diagnostics.json"',
        },
    )
