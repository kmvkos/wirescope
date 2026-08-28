from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException

from auth.service import AuthError
from backend.models import (
    AuditResponse,
    CaptureSessionResponse,
    FindingResponse,
    JobEventResponse,
    JobPageResponse,
    JobResponse,
    ReportResponse,
)
from engine.interfaces import InterfaceValidationCode, InterfaceValidationError
from engine.routes import RouteValidationError
from engine.scope import ScopeValidationError
from jobs.errors import JobExecutionError
from jobs.models import AuditRecord, JobEventRecord, JobRecord
from jobs.state import InvalidTransition


def scope_http_error(error: ScopeValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": error.code.value,
            "message": error.message,
            "details": error.details,
        },
    )


def route_http_error(error: RouteValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": error.code.value,
            "message": error.message,
            "details": error.details,
        },
    )


def interface_http_error(error: InterfaceValidationError) -> HTTPException:
    unavailable_codes = {
        InterfaceValidationCode.DISCOVERY_FAILED,
        InterfaceValidationCode.INVALID_DISCOVERY_DATA,
    }
    return HTTPException(
        status_code=503 if error.code in unavailable_codes else 422,
        detail={"code": error.code.value, "message": error.message},
    )


def audit_response(audit: AuditRecord) -> AuditResponse:
    return AuditResponse(**audit.model_dump())


def job_response(job: JobRecord) -> JobResponse:
    return JobResponse(
        id=job.id,
        audit_id=job.audit_id,
        type=job.type,
        status=job.status,
        priority=job.priority,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        updated_at=job.updated_at or job.finished_at or job.started_at or job.created_at,
        progress=job.progress,
        stage=job.stage,
        message=job.message,
        target=job.target,
        cancel_requested=job.cancel_requested,
        attempt=job.attempt,
        error=job.error,
        result_available=job.result_available,
        result_url=f"/api/jobs/{job.id}/result" if job.result_available else None,
    )


_STATS_MESSAGE = re.compile(
    r"(?P<frames>\d+) frames, (?P<bytes>\d+) bytes, (?P<elapsed>\d+)s"
)


def capture_session_response(
    job: JobRecord,
    summary: dict[str, Any] | None = None,
) -> CaptureSessionResponse:
    parameters = job.parameters or {}
    summary = summary or {}
    parsed = _STATS_MESSAGE.search(job.message) if job.message else None
    frame_count = summary.get("frame_count")
    byte_count = summary.get("byte_count") or summary.get("pcap_bytes")
    if frame_count is None and parsed is not None:
        frame_count = int(parsed.group("frames"))
    if byte_count is None and parsed is not None:
        byte_count = int(parsed.group("bytes"))
    pcap_id = summary.get("pcap_artifact_id")
    pcap_available = bool(job.result_available and pcap_id)
    return CaptureSessionResponse(
        job_id=job.id,
        audit_id=job.audit_id,
        status=job.status,
        interface=str(parameters.get("interface") or job.target or ""),
        filter=parameters.get("filter"),
        duration_seconds=parameters.get("duration_seconds"),
        max_filesize_kb=parameters.get("max_filesize_kb"),
        promiscuous=bool(parameters.get("promiscuous", True)),
        source_origin=str(
            summary.get("source_origin")
            or parameters.get("source_origin")
            or "captured"
        ),
        original_filename=(
            summary.get("original_filename")
            or parameters.get("original_filename")
        ),
        capture_format=(
            summary.get("capture_format")
            or parameters.get("capture_format")
        ),
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        progress=job.progress,
        stage=job.stage,
        message=job.message,
        frame_count=frame_count,
        byte_count=byte_count,
        pcap_bytes=summary.get("pcap_bytes") or byte_count,
        pcap_url=f"/api/jobs/{job.id}/pcap" if pcap_available else None,
        result_available=job.result_available,
        cancel_requested=job.cancel_requested,
        error=job.error,
    )


def job_page(page) -> JobPageResponse:
    return JobPageResponse(
        items=[job_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


def event_response(event: JobEventRecord) -> JobEventResponse:
    return JobEventResponse(**event.model_dump())


def finding_response(finding, *, include_events: bool = True) -> FindingResponse:
    payload = finding.model_dump(mode="json")
    if not include_events:
        payload["state_events"] = []
    return FindingResponse(**payload)


def report_response(report) -> ReportResponse:
    payload = report.model_dump(mode="json")
    payload["json_url"] = (
        f"/api/audits/{report.audit_id}/reports/{report.id}/export?format=json"
    )
    payload["html_url"] = (
        f"/api/audits/{report.audit_id}/reports/{report.id}/export?format=html"
    )
    return ReportResponse(**payload)
