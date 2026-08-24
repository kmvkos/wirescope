from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from backend.dependencies import AppServices, get_services
from backend.http import (
    invalid_transition_http,
    job_execution_http_error,
    not_found,
    report_response,
)
from backend.models import (
    JobAcceptedResponse,
    ReportJobRequest,
    ReportPageResponse,
    ReportResponse,
)
from jobs.errors import JobExecutionError
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition
from reports.markdown import render_markdown
from reports.store import ReportNotFound


router = APIRouter()


@router.post(
    "/audits/{audit_id}/reports",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_report(
    audit_id: str,
    payload: ReportJobRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="report_generation",
            target=audit.interface,
            parameters={"actor": request.state.user.username},
            priority=payload.priority,
            resource_key=f"audit:{audit.id}",
            resource_group="report",
            resource_limit=services.settings.max_report_jobs,
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except InvalidTransition as exc:
        raise invalid_transition_http(exc) from exc

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/jobs/{job.id}",
    )


@router.get("/audits/{audit_id}/reports", response_model=ReportPageResponse)
def list_reports(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    services: AppServices = Depends(get_services),
) -> ReportPageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    page = services.reports.list_reports(
        audit_id=audit_id,
        limit=limit,
        offset=offset,
    )
    return ReportPageResponse(
        items=[report_response(item) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get(
    "/audits/{audit_id}/reports/{report_id}",
    response_model=ReportResponse,
)
def get_report(
    audit_id: str,
    report_id: str,
    services: AppServices = Depends(get_services),
) -> ReportResponse:
    try:
        services.jobs.get_audit(audit_id)
        return report_response(services.reports.get(audit_id, report_id))
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except ReportNotFound as exc:
        raise not_found(exc) from exc


@router.get("/audits/{audit_id}/reports/{report_id}/export")
def export_report(
    audit_id: str,
    report_id: str,
    format: str = Query(default="json"),
    services: AppServices = Depends(get_services),
) -> Response:
    requested = format.strip().lower()
    if requested in {"md", "markdown"}:
        requested = "markdown"
    if requested == "pdf":
        raise HTTPException(
            status_code=422,
            detail={
                "code": "pdf_not_available",
                "message": "PDF export is not implemented",
            },
        )
    if requested not in {"json", "html", "markdown"}:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "unsupported_report_format",
                "message": "format must be json, html, or markdown",
            },
        )

    try:
        services.jobs.get_audit(audit_id)
        report = services.reports.get(audit_id, report_id)
        if requested == "markdown":
            json_artifact = services.jobs.artifact(report.json_artifact_id)
            if json_artifact.audit_id != audit_id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "artifact_audit_mismatch",
                        "message": "Report artifact does not belong to audit",
                    },
                )
            document = services.evidence.read_json(json_artifact)
            payload = render_markdown(document).encode("utf-8")
            media_type = "text/markdown; charset=utf-8"
        else:
            artifact_id = (
                report.json_artifact_id
                if requested == "json"
                else report.html_artifact_id
            )
            artifact = services.jobs.artifact(artifact_id)
            if artifact.audit_id != audit_id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "artifact_audit_mismatch",
                        "message": "Report artifact does not belong to audit",
                    },
                )
            payload = services.evidence.read_bytes(artifact)
            media_type = artifact.content_type
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except ReportNotFound as exc:
        raise not_found(exc) from exc
    except JobExecutionError as exc:
        raise job_execution_http_error(exc) from exc

    extension = "md" if requested == "markdown" else requested
    filename = f"wirescope-report-{report.id}.{extension}"
    disposition = "inline" if requested == "html" else "attachment"
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
        },
    )
