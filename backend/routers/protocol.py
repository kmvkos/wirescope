from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import AppServices, get_services
from backend.http import invalid_transition_http, not_found
from backend.models import (
    JobAcceptedResponse,
    ObservationPageResponse,
    ProtocolAuditRequest,
    ProtocolObservationResponse,
)
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition


router = APIRouter()


@router.post(
    "/audits/{audit_id}/protocol-audits",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_protocol_audit(
    audit_id: str,
    request: ProtocolAuditRequest,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        scope = services.inventory.latest_scope(audit.id)
        if scope is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "scope_not_confirmed",
                    "message": "Protocol audits require a confirmed authorized scope",
                },
            )

        summary = services.inventory.summary(audit.id)
        if summary.services < 1:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "inventory_empty",
                    "message": "Protocol audits require persisted inventory services",
                },
            )

        if request.modules:
            gated = [
                name
                for name in request.modules
                if services.module_registry.is_gated(name)
            ]
            unknown = [
                name
                for name in request.modules
                if name not in services.module_registry.default_names
                and name not in gated
            ]
            if gated:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "module_gated",
                        "message": "Requested protocol modules are gated off",
                        "details": {"modules": gated},
                    },
                )
            if unknown:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "unknown_module",
                        "message": "Requested protocol modules are not available",
                        "details": {"modules": unknown},
                    },
                )

        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="protocol_audit",
            target=scope.interface,
            parameters={
                "profile": request.profile,
                "modules": request.modules,
                "confirmed_scope_id": scope.id,
            },
            priority=request.priority,
            resource_key=f"audit:{audit.id}",
            resource_group="protocol_audit",
            resource_limit=services.settings.max_protocol_audit_jobs,
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except InvalidTransition as exc:
        raise invalid_transition_http(exc) from exc

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )


@router.get(
    "/audits/{audit_id}/observations",
    response_model=ObservationPageResponse,
)
def list_observations(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    asset_id: str | None = None,
    protocol: str | None = None,
    module: str | None = None,
    kind: str | None = None,
    service_id: str | None = None,
    services: AppServices = Depends(get_services),
) -> ObservationPageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    page = services.observations.list_observations(
        audit_id=audit_id,
        limit=limit,
        offset=offset,
        asset_id=asset_id,
        protocol=protocol,
        module=module,
        kind=kind,
        service_id=service_id,
    )
    return ObservationPageResponse(
        items=[
            ProtocolObservationResponse(**item.model_dump(mode="json"))
            for item in page.items
        ],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )
