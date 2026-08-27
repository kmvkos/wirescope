from __future__ import annotations

from dataclasses import asdict
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from backend.capture_deletion import (
    CapturePcapBusy,
    CapturePcapDeletionSafetyError,
    CapturePcapDeletionService,
)
from backend.dependencies import AppServices, get_services
from backend.http import (
    capture_session_response,
    interface_http_error,
    invalid_transition_http,
    job_execution_http_error,
    not_found,
)
from backend.models import (
    CaptureJobRequest,
    CaptureSessionPageResponse,
    CaptureSessionResponse,
    JobAcceptedResponse,
)
from engine.interfaces import InterfaceValidationError
from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition
from providers.bpf import BpfFilterError, normalize_bpf_filter


router = APIRouter()


def _capture_summary(job, services: AppServices) -> dict:
    """Return capture summary with raw-PCAP availability verified.

    Audit summary is historical metadata and may outlive a raw PCAP after
    retention or manual deletion. Never advertise a download URL from that
    stale reference alone.
    """

    summary = dict(services.jobs.get_audit(job.audit_id).summary or {})
    pcap_id = str(summary.get("pcap_artifact_id") or "")
    if not pcap_id:
        return summary
    try:
        artifact = services.jobs.artifact(pcap_id)
        valid = (
            artifact.audit_id == job.audit_id
            and artifact.job_id == job.id
            and artifact.artifact_type == "packet_capture"
            and services.evidence.path_for(artifact).is_file()
        )
    except EntityNotFound:
        valid = False
    if not valid:
        summary["pcap_artifact_id"] = None
    return summary


def _pcap_unavailable() -> HTTPException:
    return HTTPException(
        status_code=410,
        detail={
            "code": "pcap_unavailable",
            "message": "PCAP has been deleted or expired",
        },
    )


@router.post("/captures", response_model=JobAcceptedResponse, status_code=202)
def enqueue_capture(
    request: CaptureJobRequest,
    http_request: Request,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        interface = services.interfaces.validate(request.interface)
        try:
            filter_text = normalize_bpf_filter(
                request.filter,
                max_length=services.settings.listen_filter_max_length,
            )
        except BpfFilterError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": exc.code, "message": exc.message},
            ) from exc

        duration = (
            request.duration_seconds
            if request.duration_seconds is not None
            else services.settings.listen_duration_default
        )
        if duration < 0 or duration > services.settings.listen_duration_max:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "invalid_duration",
                    "message": (
                        "duration_seconds must be 0 (until stop) or between "
                        f"{services.settings.listen_duration_min} and "
                        f"{services.settings.listen_duration_max}"
                    ),
                },
            )
        if duration > 0 and duration < services.settings.listen_duration_min:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "invalid_duration",
                    "message": (
                        "duration_seconds must be 0 (until stop) or between "
                        f"{services.settings.listen_duration_min} and "
                        f"{services.settings.listen_duration_max}"
                    ),
                },
            )

        filesize = (
            request.max_filesize_kb
            if request.max_filesize_kb is not None
            else services.settings.listen_max_filesize_kb_default
        )
        if not 1 <= filesize <= services.settings.listen_max_filesize_kb_max:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "invalid_filesize",
                    "message": (
                        "max_filesize_kb must be between 1 and "
                        f"{services.settings.listen_max_filesize_kb_max}"
                    ),
                },
            )

        audit = services.jobs.create_audit(
            profile="packet_capture",
            interface=interface.name,
            scope={
                "filter": filter_text,
                "duration_seconds": duration,
                "max_filesize_kb": filesize,
                "promiscuous": True,
            },
            actor=http_request.state.user.username,
        )
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="packet_capture",
            target=interface.name,
            parameters={
                "interface": interface.name,
                "duration_seconds": duration,
                "max_filesize_kb": filesize,
                "filter": filter_text,
                "promiscuous": True,
            },
            priority=request.priority,
            resource_key=f"interface:{interface.name}",
            resource_group="packet_capture",
            resource_limit=services.settings.max_packet_captures,
        )
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


@router.get("/captures", response_model=CaptureSessionPageResponse)
def list_captures(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: JobStatus | None = None,
    services: AppServices = Depends(get_services),
) -> CaptureSessionPageResponse:
    page = services.jobs.list_jobs(
        limit=limit,
        offset=offset,
        status=status,
        job_type="packet_capture",
    )
    items = []
    hidden_deleted = 0
    for item in page.items:
        summary = _capture_summary(item, services)
        # Manual PCAP deletion is an explicit operator action. Keep the
        # durable capture job and normalized results addressable by ID, but do
        # not keep a dead row in the ordinary "saved PCAP" list.
        if summary.get("pcap_deleted_at"):
            hidden_deleted += 1
            continue
        items.append(capture_session_response(item, summary))
    return CaptureSessionPageResponse(
        items=items,
        limit=page.limit,
        offset=page.offset,
        # This page can only know how many manually-deleted rows occurred in
        # the selected slice. The GUI does not paginate this counter; reducing
        # it here keeps the common first-page response intuitive without
        # deleting the underlying history.
        total=max(0, page.total - hidden_deleted),
    )


@router.get("/captures/{job_id}", response_model=CaptureSessionResponse)
def get_capture(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> CaptureSessionResponse:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    if job.type != "packet_capture":
        raise HTTPException(
            status_code=404,
            detail={
                "code": "not_found",
                "message": "Capture session not found",
            },
        )
    return capture_session_response(job, _capture_summary(job, services))


@router.delete("/captures/{job_id}/pcap")
def delete_capture_pcap(
    job_id: str,
    http_request: Request,
    services: AppServices = Depends(get_services),
) -> dict:
    """Delete only the retained raw PCAP, preserving normalized history."""

    actor = getattr(getattr(http_request.state, "user", None), "username", None)
    try:
        result = CapturePcapDeletionService(
            services.database,
            services.evidence,
        ).delete(job_id, actor=actor)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except CapturePcapBusy as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "pcap_delete_busy", "message": str(exc)},
        ) from exc
    except CapturePcapDeletionSafetyError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "pcap_delete_safety_error", "message": str(exc)},
        ) from exc
    return asdict(result)


@router.get("/jobs/{job_id}/pcap")
def download_capture_pcap(
    job_id: str,
    services: AppServices = Depends(get_services),
) -> FileResponse:
    try:
        job = services.jobs.get_job(job_id)
        if job.type != "packet_capture":
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "not_found",
                    "message": "Capture session not found",
                },
            )
        if not job.result_reference:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "pcap_unavailable",
                    "message": "Capture file is not available yet",
                },
            )
        result_artifact = services.jobs.artifact(job.result_reference)
        document = services.evidence.read_json(result_artifact)
        pcap_id = document.get("pcap_artifact_id")
        if not pcap_id:
            raise _pcap_unavailable()
        try:
            pcap_artifact = services.jobs.artifact(str(pcap_id))
        except EntityNotFound as exc:
            raise _pcap_unavailable() from exc
        if (
            pcap_artifact.audit_id != job.audit_id
            or pcap_artifact.job_id != job.id
            or pcap_artifact.artifact_type != "packet_capture"
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "artifact_job_mismatch",
                    "message": "Capture artifact does not belong to job",
                },
            )
        path = services.evidence.path_for(pcap_artifact)
        if not path.is_file():
            raise _pcap_unavailable()
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc

    interface = str(
        (job.parameters or {}).get("interface") or job.target or "iface"
    )
    safe_iface = re.sub(r"[^A-Za-z0-9._-]", "_", interface)[:32] or "iface"
    filename = f"wirescope-{safe_iface}-{job.id[:8]}.pcap"
    return FileResponse(
        path=path,
        media_type="application/vnd.tcpdump.pcap",
        filename=filename,
    )