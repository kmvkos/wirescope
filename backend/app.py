import shutil
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.models import (
    AuditPageResponse,
    AuditResponse,
    CreateAuditRequest,
    HealthResponse,
    InterfaceListResponse,
    JobAcceptedResponse,
    JobEventPageResponse,
    JobEventResponse,
    JobPageResponse,
    JobResponse,
    PassiveJobRequest,
    ReadinessResponse,
)
from config.settings import Settings, get_settings
from engine.environment import get_environment
from engine.interfaces import (
    InterfaceService,
    InterfaceValidationCode,
    InterfaceValidationError,
)
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
from storage.evidence import EvidenceStore


def create_app(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    job_service: JobService | None = None,
    evidence_store: EvidenceStore | None = None,
    interface_service: InterfaceService | None = None,
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
