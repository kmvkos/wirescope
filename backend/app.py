import shutil
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.models import (
    AssetPageResponse,
    AuditPageResponse,
    AuditResponse,
    CreateAuditRequest,
    DiscoveryJobRequest,
    HealthResponse,
    InterfaceListResponse,
    InventorySummaryResponse,
    JobAcceptedResponse,
    JobEventPageResponse,
    JobEventResponse,
    JobPageResponse,
    JobResponse,
    ObservationPageResponse,
    PassiveJobRequest,
    ProtocolAuditRequest,
    ProtocolObservationResponse,
    ReadinessResponse,
    ServicePageResponse,
)
from config.settings import Settings, get_settings
from engine.active_profiles import profile_for
from engine.environment import get_environment
from engine.interfaces import (
    InterfaceService,
    InterfaceValidationCode,
    InterfaceValidationError,
)
from engine.routes import RouteResolver, RouteValidationError
from engine.scope import ScopeValidationError, ScopeValidator
from inventory.models import AssetRecord, AssetState, DeviceClassHint
from inventory.service import InventoryService
from jobs.errors import JobExecutionError
from jobs.models import (
    AuditRecord,
    AuditStatus,
    JobEventRecord,
    JobRecord,
    JobStatus,
    RetentionClass,
)
from jobs.service import EntityNotFound, JobService
from jobs.state import InvalidTransition
from persistence.database import Database
from persistence.schema import migrations_current
from protocol_audits.registry import default_registry
from protocol_audits.store import ProtocolObservationStore
from storage.evidence import EvidenceStore


def create_app(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    job_service: JobService | None = None,
    evidence_store: EvidenceStore | None = None,
    interface_service: InterfaceService | None = None,
    route_resolver: RouteResolver | None = None,
    inventory_service: InventoryService | None = None,
    observation_store: ProtocolObservationStore | None = None,
    environment_provider: Callable[[], dict[str, Any]] = get_environment,
) -> FastAPI:
    active_settings = settings or get_settings()
    active_database = database or Database(active_settings)
    active_jobs = job_service or JobService(active_database)
    active_evidence = evidence_store or EvidenceStore(
        active_database,
        active_settings,
    )
    active_interfaces = interface_service or InterfaceService(
        settings=active_settings
    )
    active_routes = route_resolver or RouteResolver(
        interfaces=active_interfaces
    )
    active_inventory = inventory_service or InventoryService(
        active_database,
        active_settings,
        active_evidence,
    )
    active_observations = observation_store or ProtocolObservationStore(
        active_database
    )
    module_registry = default_registry()

    application = FastAPI(
        title=active_settings.app_name,
        version=active_settings.app_version,
        openapi_url=(
            "/openapi.json" if active_settings.docs_enabled else None
        ),
        docs_url="/docs" if active_settings.docs_enabled else None,
        redoc_url="/redoc" if active_settings.docs_enabled else None,
    )
    application.state.settings = active_settings
    application.state.database = active_database
    application.state.jobs = active_jobs
    application.state.evidence = active_evidence
    application.state.interfaces = active_interfaces
    application.state.routes = active_routes
    application.state.inventory = active_inventory
    application.state.observations = active_observations

    @application.get("/api/health", response_model=HealthResponse)
    @application.get("/api/status", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            product=active_settings.app_name,
            version=active_settings.app_version,
        )

    @application.get("/api/ready", response_model=ReadinessResponse)
    def ready() -> ReadinessResponse:
        database_ready = active_database.is_accessible()
        migration_ready = database_ready and migrations_current(
            active_database,
            active_settings.project_root,
        )
        worker_ready = migration_ready and active_jobs.worker_is_ready(
            active_settings.worker_stale_after_seconds
        )
        dependencies = {
            "dumpcap": shutil.which(active_settings.dumpcap_binary) is not None,
            "tshark": shutil.which(active_settings.tshark_binary) is not None,
            "nmap": shutil.which(active_settings.nmap_binary) is not None,
        }
        ready_state = (
            database_ready
            and migration_ready
            and worker_ready
            and all(dependencies.values())
        )
        response = ReadinessResponse(
            status="ready" if ready_state else "not_ready",
            database=database_ready,
            migrations=migration_ready,
            worker=worker_ready,
            dependencies=dependencies,
        )
        if not ready_state:
            raise HTTPException(
                status_code=503,
                detail=response.model_dump(mode="json"),
            )
        return response

    @application.get("/api/environment")
    def api_environment() -> dict[str, Any]:
        return environment_provider()

    @application.get(
        "/api/interfaces",
        response_model=InterfaceListResponse,
    )
    def api_interfaces() -> InterfaceListResponse:
        try:
            discovery = active_interfaces.discover()
        except InterfaceValidationError as exc:
            raise _interface_http_error(exc) from exc
        return InterfaceListResponse(interfaces=discovery.interfaces)

    @application.post(
        "/api/audits",
        response_model=AuditResponse,
        status_code=201,
    )
    def create_audit(request: CreateAuditRequest) -> AuditResponse:
        try:
            active_interfaces.validate(request.interface)
        except InterfaceValidationError as exc:
            raise _interface_http_error(exc) from exc
        audit = active_jobs.create_audit(
            profile=request.profile,
            interface=request.interface,
            scope=request.scope,
            actor=request.actor,
        )
        try:
            snapshot = active_evidence.put_json(
                audit_id=audit.id,
                job_id=None,
                artifact_type="environment_snapshot",
                document={
                    "schema": "environment-snapshot",
                    "schema_version": 1,
                    "environment": environment_provider(),
                },
                retention_class=RetentionClass.AUDIT,
                schema_name="environment-snapshot",
                schema_version=1,
            )
            audit = active_jobs.set_environment_reference(
                audit.id,
                snapshot.id,
            )
        except JobExecutionError as exc:
            active_jobs.fail_audit(audit.id, exc.error)
            raise _job_execution_http_error(exc) from exc
        return _audit_response(audit)

    @application.get(
        "/api/audits",
        response_model=AuditPageResponse,
    )
    def list_audits(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        status: AuditStatus | None = None,
    ) -> AuditPageResponse:
        page = active_jobs.list_audits(
            limit=limit,
            offset=offset,
            status=status,
        )
        return AuditPageResponse(
            items=[_audit_response(item) for item in page.items],
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    @application.get(
        "/api/audits/{audit_id}",
        response_model=AuditResponse,
    )
    def get_audit(audit_id: str) -> AuditResponse:
        try:
            return _audit_response(active_jobs.get_audit(audit_id))
        except EntityNotFound as exc:
            raise _not_found(exc) from exc

    @application.post(
        "/api/audits/{audit_id}/passive",
        response_model=JobAcceptedResponse,
        status_code=202,
    )
    def enqueue_passive(
        audit_id: str,
        request: PassiveJobRequest,
    ) -> JobAcceptedResponse:
        try:
            audit = active_jobs.get_audit(audit_id)
            if not audit.interface:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "interface_required",
                        "message": "Audit has no capture interface",
                    },
                )
            active_interfaces.validate(audit.interface)
            duration = (
                request.duration_seconds
                if request.duration_seconds is not None
                else active_settings.passive_duration_default
            )
            if not (
                active_settings.passive_duration_min
                <= duration
                <= active_settings.passive_duration_max
            ):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "invalid_duration",
                        "message": (
                            "duration_seconds must be between "
                            f"{active_settings.passive_duration_min} and "
                            f"{active_settings.passive_duration_max}"
                        ),
                    },
                )
            job = active_jobs.create_job(
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
                resource_limit=active_settings.max_packet_captures,
            )
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        except InterfaceValidationError as exc:
            raise _interface_http_error(exc) from exc
        except InvalidTransition as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "invalid_state_transition",
                    "message": str(exc),
                },
            ) from exc
        return JobAcceptedResponse(
            audit_id=audit.id,
            job_id=job.id,
            status=job.status,
            status_url=f"/api/jobs/{job.id}",
        )

    @application.post(
        "/api/audits/{audit_id}/discovery",
        response_model=JobAcceptedResponse,
        status_code=202,
    )
    def enqueue_discovery(
        audit_id: str,
        request: DiscoveryJobRequest,
    ) -> JobAcceptedResponse:
        try:
            audit = active_jobs.get_audit(audit_id)
            if audit.interface and request.interface != audit.interface:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "interface_mismatch",
                        "message": (
                            "Discovery interface must match the audit interface"
                        ),
                    },
                )
            active_interfaces.validate(request.interface)
            scope = ScopeValidator(active_settings).validate(
                request.scope,
                request.profile,
            )
            resolved = active_routes.resolve(request.interface, scope)
            scan_profile = profile_for(request.profile, active_settings)
            confirmed = active_inventory.confirm_scope(
                audit_id=audit.id,
                scope=scope,
                interface=request.interface,
                route_context=resolved.model_dump(mode="json"),
                actor=audit.actor,
                timing_policy=scan_profile.timing,
            )
            job = active_jobs.create_job(
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
                resource_limit=active_settings.max_active_discovery_jobs,
            )
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        except InterfaceValidationError as exc:
            raise _interface_http_error(exc) from exc
        except ScopeValidationError as exc:
            raise _scope_http_error(exc) from exc
        except RouteValidationError as exc:
            raise _route_http_error(exc) from exc
        except InvalidTransition as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "invalid_state_transition",
                    "message": str(exc),
                },
            ) from exc
        return JobAcceptedResponse(
            audit_id=audit.id,
            job_id=job.id,
            status=job.status,
            status_url=f"/api/jobs/{job.id}",
        )

    @application.get(
        "/api/audits/{audit_id}/assets",
        response_model=AssetPageResponse,
    )
    def list_assets(
        audit_id: str,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        address: str | None = None,
        hostname: str | None = None,
        mac: str | None = None,
        vendor: str | None = None,
        state: AssetState | None = None,
        device_class: DeviceClassHint | None = None,
    ) -> AssetPageResponse:
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        page = active_inventory.list_assets(
            audit_id=audit_id,
            limit=limit,
            offset=offset,
            address=address,
            hostname=hostname,
            mac=mac,
            vendor=vendor,
            state=state,
            device_class=device_class,
        )
        return AssetPageResponse(
            items=page.items,
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    @application.get(
        "/api/audits/{audit_id}/assets/{asset_id}",
        response_model=AssetRecord,
    )
    def get_asset(audit_id: str, asset_id: str):
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        asset = active_inventory.get_asset(audit_id, asset_id)
        if asset is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "not_found",
                    "message": f"Asset not found: {asset_id}",
                },
            )
        return asset

    @application.get(
        "/api/audits/{audit_id}/services",
        response_model=ServicePageResponse,
    )
    def list_services(
        audit_id: str,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        asset_id: str | None = None,
        protocol: str | None = None,
        port: int | None = Query(default=None, ge=0, le=65_535),
        state: str | None = None,
        service_name: str | None = None,
        product: str | None = None,
    ) -> ServicePageResponse:
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        page = active_inventory.list_services(
            audit_id=audit_id,
            limit=limit,
            offset=offset,
            asset_id=asset_id,
            protocol=protocol,
            port=port,
            state=state,
            service_name=service_name,
            product=product,
        )
        return ServicePageResponse(
            items=page.items,
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    @application.get(
        "/api/audits/{audit_id}/inventory",
        response_model=InventorySummaryResponse,
    )
    def inventory_summary(audit_id: str) -> InventorySummaryResponse:
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        return InventorySummaryResponse(
            **active_inventory.summary(audit_id).model_dump()
        )

    @application.post(
        "/api/audits/{audit_id}/protocol-audits",
        response_model=JobAcceptedResponse,
        status_code=202,
    )
    def enqueue_protocol_audit(
        audit_id: str,
        request: ProtocolAuditRequest,
    ) -> JobAcceptedResponse:
        try:
            audit = active_jobs.get_audit(audit_id)
            scope = active_inventory.latest_scope(audit.id)
            if scope is None:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "scope_not_confirmed",
                        "message": (
                            "Protocol audits require a confirmed authorized scope"
                        ),
                    },
                )
            summary = active_inventory.summary(audit.id)
            if summary.services < 1:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "inventory_empty",
                        "message": (
                            "Protocol audits require persisted inventory services"
                        ),
                    },
                )
            if request.modules:
                gated = [
                    name
                    for name in request.modules
                    if module_registry.is_gated(name)
                ]
                unknown = [
                    name
                    for name in request.modules
                    if name not in module_registry.default_names
                    and name not in gated
                ]
                if gated:
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "code": "module_gated",
                            "message": (
                                "Requested protocol modules are gated off"
                            ),
                            "details": {"modules": gated},
                        },
                    )
                if unknown:
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "code": "unknown_module",
                            "message": (
                                "Requested protocol modules are not available"
                            ),
                            "details": {"modules": unknown},
                        },
                    )
            job = active_jobs.create_job(
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
                resource_limit=active_settings.max_protocol_audit_jobs,
            )
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        except InvalidTransition as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "invalid_state_transition",
                    "message": str(exc),
                },
            ) from exc
        return JobAcceptedResponse(
            audit_id=audit.id,
            job_id=job.id,
            status=job.status,
            status_url=f"/api/jobs/{job.id}",
        )

    @application.get(
        "/api/audits/{audit_id}/observations",
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
    ) -> ObservationPageResponse:
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        page = active_observations.list_observations(
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
                ProtocolObservationResponse(
                    **item.model_dump(mode="json")
                )
                for item in page.items
            ],
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    @application.get(
        "/api/audits/{audit_id}/jobs",
        response_model=JobPageResponse,
    )
    def audit_jobs(
        audit_id: str,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        status: JobStatus | None = None,
    ) -> JobPageResponse:
        try:
            active_jobs.get_audit(audit_id)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        page = active_jobs.list_jobs(
            limit=limit,
            offset=offset,
            status=status,
            audit_id=audit_id,
        )
        return _job_page(page)

    @application.get("/api/jobs", response_model=JobPageResponse)
    def list_jobs(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        status: JobStatus | None = None,
        audit_id: str | None = None,
    ) -> JobPageResponse:
        return _job_page(
            active_jobs.list_jobs(
                limit=limit,
                offset=offset,
                status=status,
                audit_id=audit_id,
            )
        )

    @application.get(
        "/api/jobs/{job_id}",
        response_model=JobResponse,
    )
    def get_job(job_id: str) -> JobResponse:
        try:
            return _job_response(active_jobs.get_job(job_id))
        except EntityNotFound as exc:
            raise _not_found(exc) from exc

    @application.post(
        "/api/jobs/{job_id}/cancel",
        response_model=JobResponse,
    )
    def cancel_job(job_id: str) -> JobResponse:
        try:
            return _job_response(active_jobs.request_cancel(job_id))
        except EntityNotFound as exc:
            raise _not_found(exc) from exc

    @application.get(
        "/api/jobs/{job_id}/events",
        response_model=JobEventPageResponse,
    )
    def job_events(
        job_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> JobEventPageResponse:
        try:
            page = active_jobs.list_events(
                job_id,
                limit=limit,
                offset=offset,
            )
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        return JobEventPageResponse(
            items=[_event_response(item) for item in page.items],
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    @application.get("/api/jobs/{job_id}/result")
    def job_result(job_id: str) -> dict[str, Any]:
        try:
            job = active_jobs.get_job(job_id)
            if not job.result_reference:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "result_unavailable",
                        "message": "Job result is not available",
                    },
                )
            artifact = active_jobs.artifact(job.result_reference)
            if artifact.job_id != job.id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "result_reference_mismatch",
                        "message": "Result artifact does not belong to job",
                    },
                )
            return active_evidence.read_json(artifact)
        except EntityNotFound as exc:
            raise _not_found(exc) from exc
        except JobExecutionError as exc:
            raise _job_execution_http_error(exc) from exc

    application.mount(
        "/static",
        StaticFiles(directory=str(active_settings.frontend_dir)),
        name="static",
    )

    @application.get("/")
    def root() -> FileResponse:
        return FileResponse(active_settings.frontend_dir / "index.html")

    return application


def _scope_http_error(error: ScopeValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": error.code.value,
            "message": error.message,
            "details": error.details,
        },
    )


def _route_http_error(error: RouteValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": error.code.value,
            "message": error.message,
            "details": error.details,
        },
    )


def _interface_http_error(
    error: InterfaceValidationError,
) -> HTTPException:
    unavailable_codes = {
        InterfaceValidationCode.DISCOVERY_FAILED,
        InterfaceValidationCode.INVALID_DISCOVERY_DATA,
    }
    return HTTPException(
        status_code=503 if error.code in unavailable_codes else 422,
        detail={
            "code": error.code.value,
            "message": error.message,
        },
    )


def _audit_response(audit: AuditRecord) -> AuditResponse:
    return AuditResponse(**audit.model_dump())


def _job_response(job: JobRecord) -> JobResponse:
    return JobResponse(
        id=job.id,
        audit_id=job.audit_id,
        type=job.type,
        status=job.status,
        priority=job.priority,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        progress=job.progress,
        stage=job.stage,
        message=job.message,
        target=job.target,
        cancel_requested=job.cancel_requested,
        attempt=job.attempt,
        error=job.error,
        result_available=job.result_available,
        result_url=(
            f"/api/jobs/{job.id}/result" if job.result_available else None
        ),
    )


def _job_page(page) -> JobPageResponse:
    return JobPageResponse(
        items=[_job_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


def _event_response(event: JobEventRecord) -> JobEventResponse:
    return JobEventResponse(**event.model_dump())


def _not_found(error: EntityNotFound) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "code": "not_found",
            "message": str(error),
        },
    )


def _job_execution_http_error(error: JobExecutionError) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=error.error.model_dump(mode="json"),
    )


app = create_app()
