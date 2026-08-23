from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.models import (
    InterfaceListResponse,
    JobResponse,
    PassiveStartRequest,
    PassiveStartResponse,
)
from config.settings import get_settings
from engine.environment import get_environment
from engine.interfaces import (
    InterfaceService,
    InterfaceValidationCode,
    InterfaceValidationError,
)
from engine.jobs import (
    create_job,
    get_job,
    list_jobs
)
from engine.passive import passive_discovery


settings = get_settings()
interface_service = InterfaceService(settings=settings)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
)


@app.get("/api/status")
def api_status():
    return {
        "status": "ok",
        "product": settings.app_name,
        "version": settings.app_version
    }


@app.get("/api/environment")
def api_environment():
    return get_environment()


@app.get("/api/interfaces", response_model=InterfaceListResponse)
def api_interfaces():
    try:
        discovery = interface_service.discover()
    except InterfaceValidationError as exc:
        raise _interface_http_error(exc) from exc
    return InterfaceListResponse(interfaces=discovery.interfaces)


app.mount(
    "/static",
    StaticFiles(directory=str(settings.frontend_dir)),
    name="static"
)


@app.get("/")
def root():
    return FileResponse(
        settings.frontend_dir / "index.html"
    )

@app.post(
    "/api/passive/start",
    response_model=PassiveStartResponse,
)
def start_passive_scan(
    request: PassiveStartRequest,
):
    try:
        interface_service.validate(request.interface)
    except InterfaceValidationError as exc:
        raise _interface_http_error(exc) from exc

    duration = (
        request.duration_seconds
        if request.duration_seconds is not None
        else settings.passive_duration_default
    )
    job_id = create_job(
        job_type="passive_discovery",
        target=request.interface,
        function=passive_discovery,
        interface=request.interface,
        duration=duration
    )

    return PassiveStartResponse(
        job_id=job_id,
        status="queued",
    )


@app.get("/api/jobs/{job_id}", response_model=JobResponse)
def job_status(job_id: str):

    job = get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    return job


@app.get("/api/jobs", response_model=list[JobResponse])
def jobs():

    return list_jobs()


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
