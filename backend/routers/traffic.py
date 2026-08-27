from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select

from backend.dependencies import AppServices, get_services
from backend.http import job_execution_http_error, not_found
from backend.models import JobAcceptedResponse
from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from persistence.models import AuditModel, JobModel
from traffic_analysis.compare import compare_traffic_analysis, render_comparison_text
from traffic_analysis.service import (
    TrafficAnalysisJobService,
    TrafficAnalysisSourceNotReady,
)


router = APIRouter()


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _pcap_unavailable(message: str = "Capture PCAP is unavailable") -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"code": "pcap_unavailable", "message": message},
    )


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
        raise _pcap_unavailable("Capture has no retained PCAP result")

    try:
        result_artifact = services.jobs.artifact(job.result_reference)
        document = services.evidence.read_json(result_artifact)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc

    pcap_artifact_id = str(document.get("pcap_artifact_id") or "")
    if not pcap_artifact_id:
        raise _pcap_unavailable()
    try:
        pcap_artifact = services.jobs.artifact(pcap_artifact_id)
    except EntityNotFound as exc:
        # Manual/retention deletion intentionally removes the raw artifact row
        # while preserving capture_result and completed normalized analyses.
        # Treat that state as an unavailable source, not as a missing capture.
        raise _pcap_unavailable("Capture PCAP has been deleted or expired") from exc

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
    if not services.evidence.path_for(pcap_artifact).is_file():
        # Do not enqueue a worker job that can only fail because the retained
        # file disappeared outside the normal metadata lifecycle.
        raise _pcap_unavailable("Capture PCAP file has been deleted or expired")
    return job, pcap_artifact


def _analysis_document(job_id: str, services: AppServices):
    try:
        job = services.jobs.get_job(job_id)
        if job.type != "traffic_analysis":
            raise HTTPException(
                status_code=404,
                detail={"code": "not_found", "message": "Traffic analysis job not found"},
            )
        if job.status != JobStatus.COMPLETED or not job.result_reference:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "traffic_analysis_unavailable",
                    "message": "Traffic analysis result is not completed",
                },
            )
        artifact = services.jobs.artifact(job.result_reference)
        if artifact.job_id != job.id or artifact.artifact_type != "traffic_analysis_result":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "traffic_analysis_reference_mismatch",
                    "message": "Traffic analysis result does not belong to this job",
                },
            )
        return job, services.evidence.read_json(artifact)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc


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


@router.get("/traffic-analysis")
def list_traffic_analyses(
    limit: int = Query(default=50, ge=1, le=200),
    services: AppServices = Depends(get_services),
) -> dict:
    with services.database.session() as session:
        rows = session.execute(
            select(JobModel, AuditModel)
            .join(AuditModel, AuditModel.id == JobModel.audit_id)
            .where(
                JobModel.type == "traffic_analysis",
                JobModel.status == JobStatus.COMPLETED.value,
                JobModel.result_reference.is_not(None),
            )
            .order_by(JobModel.created_at.desc())
            .limit(limit)
        ).all()
        items = []
        for job, audit in rows:
            parameters = dict(job.parameters or {})
            items.append(
                {
                    "job_id": job.id,
                    "audit_id": job.audit_id,
                    "capture_job_id": parameters.get("source_capture_job_id"),
                    "analyzer_version": parameters.get("analyzer_version"),
                    "interface": audit.interface,
                    "created_at": _iso_utc(job.created_at),
                    "finished_at": _iso_utc(job.finished_at),
                }
            )
    return {"items": items}


@router.get("/jobs/{job_id}/traffic-analysis/compare")
def compare_traffic_analyses(
    job_id: str,
    against: str = Query(min_length=1),
    format: str = Query(default="json"),
    services: AppServices = Depends(get_services),
):
    if job_id == against:
        raise HTTPException(
            status_code=422,
            detail={"code": "same_analysis", "message": "Choose two different traffic analyses"},
        )
    current_job, current = _analysis_document(job_id, services)
    baseline_job, baseline = _analysis_document(against, services)
    comparison = compare_traffic_analysis(
        baseline=baseline,
        current=current,
        baseline_job_id=baseline_job.id,
        current_job_id=current_job.id,
    )
    requested = format.strip().lower()
    if requested in {"text", "txt"}:
        return Response(
            content=render_comparison_text(comparison).encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'inline; filename="wirescope-traffic-compare-{against[:8]}-{job_id[:8]}.txt"'
                )
            },
        )
    if requested != "json":
        raise HTTPException(
            status_code=422,
            detail={"code": "unsupported_comparison_format", "message": "format must be json or text"},
        )
    return comparison


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
