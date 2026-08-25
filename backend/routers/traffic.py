from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from backend.dependencies import AppServices, get_services
from backend.http import job_execution_http_error, not_found
from backend.models import JobAcceptedResponse
from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from traffic_analysis.service import (
    TrafficAnalysisJobService,
    TrafficAnalysisSourceNotReady,
)


router = APIRouter()


def _source_capture(job_id: str, services: AppServices):
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    if job.type != "packet_capture":
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Capture session not found"},
        )
    if job.status not in {JobStatus.COMPLETED, JobStatus.CANCELLED}:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "capture_not_ready_for_analysis",
                "message": "Finish or stop the capture before traffic analysis",
            },
        )
    if not job.result_reference:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "pcap_unavailable",
                "message": "Capture has no retained PCAP result",
            },
        )
    try:
        result_artifact = services.jobs.artifact(job.result_reference)
        document = services.evidence.read_json(result_artifact)
        pcap_artifact_id = str(document.get("pcap_artifact_id") or "")
        if not pcap_artifact_id:
            raise HTTPException(
                status_code=409,
                detail={"code": "pcap_unavailable", "message": "Capture PCAP is unavailable"},
            )
        pcap_artifact = services.jobs.artifact(pcap_artifact_id)
        if (
            pcap_artifact.audit_id != job.audit_id
            or pcap_artifact.job_id != job.id
            or pcap_artifact.artifact_type != "packet_capture"
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "pcap_reference_mismatch",
                    "message": "Stored PCAP does not belong to this capture",
                },
            )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc
    return job, pcap_artifact


@router.post(
    "/captures/{capture_job_id}/analyze",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_traffic_analysis(
    capture_job_id: str,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    capture, pcap = _source_capture(capture_job_id, services)
    try:
        job_id = TrafficAnalysisJobService(services.database).enqueue(
            audit_id=capture.audit_id,
            source_capture_job_id=capture.id,
            pcap_artifact_id=pcap.id,
        )
        job = services.jobs.get_job(job_id)
    except TrafficAnalysisSourceNotReady as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "traffic_analysis_busy", "message": str(exc)},
        ) from exc
    except LookupError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    return JobAcceptedResponse(
        audit_id=job.audit_id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )


@router.get("/jobs/{job_id}/traffic-analysis/export")
def export_traffic_analysis(
    job_id: str,
    format: str = Query(default="text"),
    services: AppServices = Depends(get_services),
) -> Response:
    requested = format.strip().lower()
    if requested == "txt":
        requested = "text"
    if requested == "md":
        requested = "markdown"
    if requested not in {"text", "markdown", "json"}:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "unsupported_traffic_analysis_format",
                "message": "format must be text, markdown, or json",
            },
        )
    try:
        job = services.jobs.get_job(job_id)
        if job.type != "traffic_analysis":
            raise HTTPException(
                status_code=404,
                detail={"code": "not_found", "message": "Traffic analysis job not found"},
            )
        if not job.result_reference:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "traffic_analysis_unavailable",
                    "message": "Traffic analysis result is not available yet",
                },
            )
        result_artifact = services.jobs.artifact(job.result_reference)
        if result_artifact.job_id != job.id:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "traffic_analysis_reference_mismatch",
                    "message": "Traffic analysis result does not belong to this job",
                },
            )
        if requested == "json":
            artifact = result_artifact
            extension = "json"
            media_type = "application/json"
        else:
            document = services.evidence.read_json(result_artifact)
            artifacts = document.get("artifacts") or {}
            key = "text_artifact_id" if requested == "text" else "markdown_artifact_id"
            artifact_id = str(artifacts.get(key) or "")
            if not artifact_id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "traffic_analysis_export_unavailable",
                        "message": "Requested traffic analysis export is unavailable",
                    },
                )
            artifact = services.jobs.artifact(artifact_id)
            if artifact.job_id != job.id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "traffic_analysis_reference_mismatch",
                        "message": "Traffic analysis export does not belong to this job",
                    },
                )
            extension = "txt" if requested == "text" else "md"
            media_type = (
                "text/plain; charset=utf-8"
                if requested == "text"
                else "text/markdown; charset=utf-8"
            )
        payload = services.evidence.read_bytes(artifact)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc

    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="wirescope-traffic-{job.id[:8]}.{extension}"'
            )
        },
    )
