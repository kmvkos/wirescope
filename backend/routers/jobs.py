from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import AppServices, get_services
from backend.http import (
    event_response,
    job_execution_http_error,
    job_page,
    job_response,
    not_found,
)
from backend.models import JobEventPageResponse, JobPageResponse, JobResponse
from backend.snmp_credentials import CredentialReferenceError, SnmpCredentialSpool
from backend.ssh_credentials import SshCredentialReferenceError, SshCredentialSpool
from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound


router = APIRouter()


@router.get("/audits/{audit_id}/jobs", response_model=JobPageResponse)
def audit_jobs(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: JobStatus | None = None,
    services: AppServices = Depends(get_services),
) -> JobPageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    page = services.jobs.list_jobs(
        limit=limit,
        offset=offset,
        status=status,
        audit_id=audit_id,
    )
    return JobPageResponse(
        items=[job_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get("/jobs", response_model=JobPageResponse)
def list_jobs(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: JobStatus | None = None,
    audit_id: str | None = None,
    job_type: str | None = Query(default=None, max_length=64),
    services: AppServices = Depends(get_services),
) -> JobPageResponse:
    return job_page(
        services.jobs.list_jobs(
            limit=limit,
            offset=offset,
            status=status,
            audit_id=audit_id,
            job_type=job_type,
        )
    )


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> JobResponse:
    try:
        return job_response(services.jobs.get_job(job_id))
    except EntityNotFound as exc:
        raise not_found(exc) from exc


def _delete_queued_management_credentials(services: AppServices, job) -> None:
    reference = str(job.parameters.get("credential_ref") or "")
    if not reference:
        return
    if job.type == "snmp_topology":
        try:
            SnmpCredentialSpool(services.settings).delete(reference)
        except CredentialReferenceError:
            pass
    elif job.type == "ssh_topology":
        try:
            SshCredentialSpool(services.settings).delete(reference)
        except SshCredentialReferenceError:
            pass


@router.post("/jobs/{job_id}/cancel", response_model=JobResponse)
def cancel_job(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> JobResponse:
    try:
        before = services.jobs.get_job(job_id)
        result = services.jobs.request_cancel(job_id)
        # A queued job never reaches the worker, so its consume-once secret
        # spool must be removed here. Running jobs delete it in the handler's
        # finally block after the cancellation token stops the tool process.
        if (
            before.type in {"snmp_topology", "ssh_topology"}
            and before.status == JobStatus.QUEUED
            and result.status == JobStatus.CANCELLED
        ):
            _delete_queued_management_credentials(services, before)
        return job_response(result)
    except EntityNotFound as exc:
        raise not_found(exc) from exc


@router.get("/jobs/{job_id}/events", response_model=JobEventPageResponse)
def job_events(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    services: AppServices = Depends(get_services),
) -> JobEventPageResponse:
    try:
        page = services.jobs.list_events(
            job_id,
            limit=limit,
            offset=offset,
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    return JobEventPageResponse(
        items=[event_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get("/jobs/{job_id}/result")
def job_result(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    try:
        job = services.jobs.get_job(job_id)
        if not job.result_reference:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "result_unavailable",
                    "message": "Job result is not available",
                },
            )
        artifact = services.jobs.artifact(job.result_reference)
        if artifact.job_id != job.id:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "result_reference_mismatch",
                    "message": "Result artifact does not belong to job",
                },
            )
        return services.evidence.read_json(artifact)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc
