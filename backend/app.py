from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from auth.service import AuthService
from backend.audit_log import AuditLogService, audit_id_from_path, operational_action
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


_UI_ASSET_VERSION = "20260825-ui11"


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
    active_audit_log = AuditLogService(active_database)
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
        audit_log=active_audit_log,
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
    application.state.audit_log = active_audit_log
    application.state.network = active_network

    @application.middleware("http")
    async def operational_audit_middleware(request: Request, call_next):
        action = operational_action(request.method, request.url.path)
        if action is None:
            return await call_next(request)
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            user = getattr(request.state, "user", None)
            actor = getattr(request.state, "audit_actor", None)
            role = getattr(request.state, "audit_role", None)
            if user is not None:
                actor = actor or user.username
                role = role or user.role.value
            try:
                active_audit_log.record(
                    action=action,
                    method=request.method,
                    path=request.url.path,
                    status_code=status_code,
                    actor=actor,
                    role=role,
                    client_ip=(
                        request.client.host if request.client is not None else None
                    ),
                    audit_id=audit_id_from_path(request.url.path),
                )
            except Exception:
                # Audit logging must never turn an otherwise valid operator
                # action into an application outage. Diagnostics will expose
                # database/migration health separately.
                pass

    # /api/v1 is canonical. /api remains a compatibility alias for existing
    # installations and external clients during the v1 transition.
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

    @application.get("/", response_class=HTMLResponse)
    def root() -> HTMLResponse:
        index = active_settings.frontend_dir / "index.html"
        page = index.read_text(encoding="utf-8")
        # Cache-bust all core frontend assets. Kiosk Chromium can otherwise keep
        # an old UI across an appliance code upgrade until a manual hard reload.
        for asset in (
            "style.css",
            "enhancements.css",
            "i18n.js",
            "app.js",
            "enhancements.js",
        ):
            page = page.replace(
                f"/static/{asset}",
                f"/static/{asset}?v={_UI_ASSET_VERSION}",
            )
        page = page.replace(
            "</head>",
            (
                f'<link rel="stylesheet" href="/static/modern.css?v={_UI_ASSET_VERSION}">\n'
                f'<link rel="stylesheet" href="/static/polish.css?v={_UI_ASSET_VERSION}">\n'
                f'<link rel="stylesheet" href="/static/report_management.css?v={_UI_ASSET_VERSION}">\n'
                f'<link rel="stylesheet" href="/static/audit_management.css?v={_UI_ASSET_VERSION}">\n'
                f'<link rel="stylesheet" href="/static/traffic_analysis.css?v={_UI_ASSET_VERSION}">\n'
                f'<link rel="stylesheet" href="/static/topology.css?v={_UI_ASSET_VERSION}">\n'
                "</head>"
            ),
        )
        page = page.replace(
            '<script src="/static/enhancements.js',
            f'<script src="/static/progress_runtime.js?v={_UI_ASSET_VERSION}"></script>\n'
            '<script src="/static/enhancements.js',
            1,
        )
        page = page.replace(
            "</body>",
            (
                f'<script src="/static/report_management.js?v={_UI_ASSET_VERSION}"></script>\n'
                f'<script src="/static/audit_management.js?v={_UI_ASSET_VERSION}"></script>\n'
                f'<script src="/static/traffic_analysis.js?v={_UI_ASSET_VERSION}"></script>\n'
                f'<script src="/static/topology.js?v={_UI_ASSET_VERSION}"></script>\n'
                f'<script src="/static/topology_tab.js?v={_UI_ASSET_VERSION}"></script>\n'
                f'<script src="/static/operations.js?v={_UI_ASSET_VERSION}"></script>\n'
                "</body>"
            ),
        )
        return HTMLResponse(
            page,
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
            },
        )

    return application


app = create_app()
