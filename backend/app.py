from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from engine.passive import passive_discovery
from engine.environment import get_environment
from fastapi import HTTPException

from engine.passive import passive_discovery
from engine.jobs import (
    create_job,
    get_job,
    list_jobs
)

app = FastAPI(
    title="WireScope",
    version="0.1.0"
)


@app.get("/api/status")
def api_status():
    return {
        "status": "ok",
        "product": "WireScope",
        "version": "0.1.0"
    }


@app.get("/api/environment")
def api_environment():
    return get_environment()


app.mount(
    "/static",
    StaticFiles(directory="/opt/wirescope/frontend"),
    name="static"
)


@app.get("/")
def root():
    return FileResponse(
        "/opt/wirescope/frontend/index.html"
    )

@app.get("/api/passive/{interface}")
def api_passive(
    interface: str,
    duration: int = 20
):
    duration = max(
        5,
        min(duration, 60)
    )

    return passive_discovery(
        interface,
        duration
    )

@app.post("/api/passive/start")
def start_passive_scan(
    interface: str,
    duration: int = 30
):

    duration = max(
        5,
        min(duration, 300)
    )

    job_id = create_job(
        job_type="passive_discovery",
        target=interface,
        function=passive_discovery,
        interface=interface,
        duration=duration
    )

    return {
        "job_id": job_id,
        "status": "queued"
    }


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):

    job = get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    return job


@app.get("/api/jobs")
def jobs():

    return list_jobs()
