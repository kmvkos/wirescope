"""Manual PCAP/PCAPNG import without network side effects."""

from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.dependencies import AppServices, get_services
from backend.models import JobAcceptedResponse
from jobs.state import InvalidTransition
from storage.pcap_import import (
    PcapImportValidationError,
    import_staging_path,
    inspect_pcap_file,
    sanitize_original_filename,
)


router = APIRouter()


def _max_import_bytes() -> int:
    raw = os.getenv("WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB", "256").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "pcap_import_policy_invalid",
                "message": "WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB must be an integer",
            },
        ) from exc
    if not 1 <= value <= 4096:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "pcap_import_policy_invalid",
                "message": "WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB must be 1..4096",
            },
        )
    return value * 1024 * 1024


def _validation_http(exc: PcapImportValidationError) -> HTTPException:
    status = 413 if exc.code == "pcap_import_too_large" else 422
    return HTTPException(
        status_code=status,
        detail={"code": exc.code, "message": exc.message},
    )


@router.post(
    "/captures/import",
    response_model=JobAcceptedResponse,
    status_code=202,
)
async def import_pcap(
    http_request: Request,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    """Stage an operator-supplied capture and enqueue offline normalization.

    The body is the raw file, not multipart. This keeps uploads streaming and
    avoids buffering large PCAPs in application memory.
    """

    max_bytes = _max_import_bytes()
    content_length = http_request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            declared = 0
        if declared > max_bytes:
            raise HTTPException(
                status_code=413,
                detail={
                    "code": "pcap_import_too_large",
                    "message": "Uploaded PCAP exceeds the configured size limit",
                },
            )

    original_name = sanitize_original_filename(
        http_request.headers.get("x-wirescope-filename")
    )
    token = str(uuid.uuid4())
    staging = import_staging_path(services.evidence.root, token)
    total = 0
    try:
        with staging.open("xb") as handle:
            os.chmod(staging, 0o600)
            async for chunk in http_request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise PcapImportValidationError(
                        "pcap_import_too_large",
                        "Uploaded PCAP exceeds the configured size limit",
                    )
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())

        info = inspect_pcap_file(staging, max_bytes=max_bytes)
        actor = getattr(getattr(http_request.state, "user", None), "username", None)
        audit = services.jobs.create_audit(
            profile="packet_capture",
            interface=None,
            scope={
                "source_origin": "imported",
                "network_io": False,
                "active_scope_authorized": False,
            },
            actor=actor,
        )
        try:
            job = services.jobs.create_job(
                audit_id=audit.id,
                job_type="packet_capture",
                target=None,
                parameters={
                    "source_origin": "imported",
                    "staging_token": token,
                    "original_filename": original_name,
                    "capture_format": info.format,
                    "uploaded_bytes": info.size,
                    "upload_sha256": info.sha256,
                    "promiscuous": False,
                    "network_io": False,
                    "active_scope_authorized": False,
                },
                priority=0,
            )
        except InvalidTransition:
            staging.unlink(missing_ok=True)
            raise
    except PcapImportValidationError as exc:
        staging.unlink(missing_ok=True)
        raise _validation_http(exc) from exc
    except HTTPException:
        staging.unlink(missing_ok=True)
        raise
    except Exception:
        # If no durable job was created, do not strand a fresh upload. Once a
        # job exists the worker owns this path and will remove it in finally.
        if "job" not in locals():
            staging.unlink(missing_ok=True)
        raise

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )
