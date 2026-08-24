from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from auth.service import AuthService
from backend.dependencies import AppServices
from backend.routers import api_router
from backend.security import auth_guard
from config.settings import Settings, get_settings
from engine.environment import get_environment
from engine.interfaces import InterfaceService
from engine.network import NetworkService
from engine.routes import RouteResolver
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.service import JobService
from persistence.database import Database
from protocol_audits.registry import default_registry
from protocol_audits.store import ProtocolObservationStore
from reports.store import ReportStore
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
    finding_store: FindingStore | None = None,
    report_store: ReportStore | None = None,
    auth_service: AuthService | None = None,
    environment_provider: Callable[[], dict[str, Any]] = get_environment,
    network_service: NetworkService | None = None,
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
    active_findings = finding_store or FindingStore(active_database)
    active_reports = report_store or ReportStore(active_database)
    active_auth = auth_service or AuthService(active_database, active_settings)
    active_auth.bootstrap()
    active_network = network_service or NetworkService(active_settings)

    services = AppServices(
        settings=active_settings,
        database=active_database,
        jobs=active_jobs,
        evidence=active_evidence,
        interfaces=active_interfaces,
        routes=active_routes,
        inventory=active_inventory,
        observations=active_observations,
        findings=active_findings,
        reports=active_reports,
        auth=active_auth,
        network=active_network,
        environment_provider=environment_provider,
        module_registry=default_registry(),
    )

    application = FastAPI(
        title=active_settings.app_name,
        version=active_settings.app_version,
        openapi_url=(
            "/openapi.json" if active_settings.docs_enabled else None
        ),
        docs_url="/docs" if active_settings.docs_enabled else None,
        redoc_url="/redoc" if active_settings.docs_enabled else None,
        dependencies=[Depends(auth_guard)],
    )

    application.state.services = services
    # Keep existing state attributes for tests and integrations that use the
    # in-process application object directly.
    application.state.settings = active_settings
    application.state.database = active_database
    application.state.jobs = active_jobs
    application.state.evidence = active_evidence
    application.state.interfaces = active_interfaces
    application.state.routes = active_routes
    application.state.inventory = active_inventory
    application.state.observations = active_observations
    application.state.findings = active_findings
    application.state.reports = active_reports
    application.state.auth = active_auth
    application.state.network = active_network

    # /api/v1 is canonical. /api remains a compatibility alias while the
    # current frontend and external clients migrate.
    application.include_router(api_router, prefix="/api/v1")
    application.include_router(
        api_router,
        prefix="/api",
        include_in_schema=False,
    )

    application.mount(
        "/static",
        StaticFiles(directory=str(active_settings.frontend_dir)),
        name="static",
    )

    @application.get("/")
    def root() -> FileResponse:
        return FileResponse(active_settings.frontend_dir / "index.html")

    return application


app = create_app()
