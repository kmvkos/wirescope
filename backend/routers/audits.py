from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.dependencies import AppServices, get_services
from backend.http import (
    audit_response,
    interface_http_error,
    invalid_transition_http,
    job_execution_http_error,
    not_found,
    route_http_error,
    scope_http_error,
)
from backend.models import (
    AuditPageResponse,
    AuditResponse,
    CreateAuditRequest,
    DiscoveryJobRequest,
    JobAcceptedResponse,
    PassiveJobRequest,
)
from engine.active_profiles import profile_for
from engine.interfaces import InterfaceValidationError
from engine.routes import RouteValidationError
from engine.scope import (
    ScopeValidationError,
    ScopeValidator,
    expand_connected_network_targets,
)
from jobs.errors import JobExecutionError
from jobs.models import AuditStatus, RetentionClass
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition


router = APIRouter()


@router.post("/audits", response_model=AuditResponse, status_code=201)
def create_audit(
    payload: CreateAuditRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> AuditResponse:
    try:
        services.interfaces.validate(payload.interface)
    except InterfaceValidationError as exc:
        raise interface_http_error(exc) from exc

    audit = services.jobs.create_audit(
        profile=payload.profile,
        interface=payload.interface,
        scope=payload.scope,
        actor=request.state.user.username,
    )
    try:
        snapshot = services.evidence.put_json(
            audit_id=audit.id,
            job_id=None,
            artifact_type="environment_snapshot",
            document={
                "schema": "environment-snapshot",
                "schema_version": 1,
                "environment": services.environment_provider(),
            },
            retention_class=RetentionClass.AUDIT,
            schema_name="environment-snapshot",
            schema_version=1,
        )
        audit = services.jobs.set_environment_reference(audit.id, snapshot.id)
    except JobExecutionError as exc:
        services.jobs.fail_audit(audit.id, exc.error)
        raise job_execution_http_error(exc) from exc
    return audit_response(audit)


@router.get("/audits", response_model=AuditPageResponse)
def list_audits(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: AuditStatus | None = None,
    services: AppServices = Depends(get_services),
) -> AuditPageResponse:
    page = services.jobs.list_audits(
        limit=limit,
        offset=offset,
        status=status,
    )
    return AuditPageResponse(
        items=[audit_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get("/audits/{audit_id}", response_model=AuditResponse)
def get_audit(
    audit_id: str,
    services: AppServices = Depends(get_services),
) -> AuditResponse:
    try:
        return audit_response(services.jobs.get_audit(audit_id))
    except EntityNotFound as exc:
        raise not_found(exc) from exc


@router.post(
    "/audits/{audit_id}/passive",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_passive(
    audit_id: str,
    request: PassiveJobRequest,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        if not audit.interface:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "interface_required",
                    "message": "Audit has no capture interface",
                },
            )
        services.interfaces.validate(audit.interface)
        duration = (
            request.duration_seconds
            if request.duration_seconds is not None
            else services.settings.passive_duration_default
        )
        if not (
            services.settings.passive_duration_min
            <= duration
            <= services.settings.passive_duration_max
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "invalid_duration",
                    "message": (
                        "duration_seconds must be between "
                        f"{services.settings.passive_duration_min} and "
                        f"{services.settings.passive_duration_max}"
                    ),
                },
            )
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="passive_discovery",
            target=audit.interface,
            parameters={
                "interface": audit.interface,
                "duration_seconds": duration,
            },
            priority=request.priority,
            resource_key=f"interface:{audit.interface}",
            resource_group="packet_capture",
            resource_limit=services.settings.max_packet_captures,
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except InterfaceValidationError as exc:
        raise interface_http_error(exc) from exc
    except InvalidTransition as exc:
        raise invalid_transition_http(exc) from exc

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )


@router.post(
    "/audits/{audit_id}/discovery",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_discovery(
    audit_id: str,
    request: DiscoveryJobRequest,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        if audit.interface and request.interface != audit.interface:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "interface_mismatch",
                    "message": "Discovery interface must match the audit interface",
                },
            )
        interface = services.interfaces.validate(request.interface)
        expanded = expand_connected_network_targets(
            request.scope,
            assigned=[*interface.ipv4, *interface.ipv6],
        )
        validator = ScopeValidator(services.settings)
        scope = validator.validate(expanded, request.profile)
        resolved = services.routes.resolve(request.interface, scope)
        routable = [route.target for route in resolved.routes]
        if set(routable) != set(scope.canonical_targets):
            scope = validator.validate(routable, request.profile)
        scan_profile = profile_for(request.profile, services.settings)
        confirmed = services.inventory.confirm_scope(
            audit_id=audit.id,
            scope=scope,
            interface=request.interface,
            route_context=resolved.model_dump(mode="json"),
            actor=audit.actor,
            timing_policy=scan_profile.timing,
        )
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="active_discovery",
            target=request.interface,
            parameters={
                "interface": request.interface,
                "scope": scope.canonical_targets,
                "profile": request.profile.value,
                "confirmed_scope_id": confirmed.id,
            },
            priority=request.priority,
            resource_key=f"interface:{request.interface}",
            resource_group="active_discovery",
            resource_limit=services.settings.max_active_discovery_jobs,
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except InterfaceValidationError as exc:
        raise interface_http_error(exc) from exc
    except ScopeValidationError as exc:
        raise scope_http_error(exc) from exc
    except RouteValidationError as exc:
        raise route_http_error(exc) from exc
    except InvalidTransition as exc:
        raise invalid_transition_http(exc) from exc

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )
