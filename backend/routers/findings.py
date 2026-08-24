from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.dependencies import AppServices, get_services
from backend.http import finding_response, invalid_transition_http, not_found
from backend.models import (
    FindingPageResponse,
    FindingResponse,
    FindingStateChangeRequest,
    FindingsJobRequest,
    JobAcceptedResponse,
)
from findings.models import FindingStatus, Severity
from findings.store import FindingNotFound, InvalidFindingState
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition


router = APIRouter()


@router.post(
    "/audits/{audit_id}/findings",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_findings(
    audit_id: str,
    request: FindingsJobRequest,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    try:
        audit = services.jobs.get_audit(audit_id)
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="findings_evaluation",
            target=audit.interface,
            parameters={},
            priority=request.priority,
            resource_key=f"audit:{audit.id}",
            resource_group="findings",
            resource_limit=services.settings.max_findings_jobs,
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


@router.get(
    "/audits/{audit_id}/findings",
    response_model=FindingPageResponse,
)
def list_findings(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    asset_id: str | None = None,
    service_id: str | None = None,
    rule_id: str | None = None,
    family: str | None = None,
    services: AppServices = Depends(get_services),
) -> FindingPageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    page = services.findings.list_findings(
        audit_id=audit_id,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        asset_id=asset_id,
        service_id=service_id,
        rule_id=rule_id,
        family=family,
    )
    return FindingPageResponse(
        items=[finding_response(item, include_events=False) for item in page.items],
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get(
    "/audits/{audit_id}/findings/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    audit_id: str,
    finding_id: str,
    services: AppServices = Depends(get_services),
) -> FindingResponse:
    try:
        services.jobs.get_audit(audit_id)
        return finding_response(
            services.findings.get_finding(
                audit_id=audit_id,
                finding_id=finding_id,
                include_events=True,
            )
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except FindingNotFound as exc:
        raise not_found(exc) from exc


def _change_finding_status(
    audit_id: str,
    finding_id: str,
    to_status: FindingStatus,
    payload: FindingStateChangeRequest,
    request: Request,
    services: AppServices,
) -> FindingResponse:
    try:
        services.jobs.get_audit(audit_id)
        return finding_response(
            services.findings.change_status(
                audit_id=audit_id,
                finding_id=finding_id,
                to_status=to_status,
                actor=request.state.user.username,
                reason=payload.reason,
            )
        )
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    except FindingNotFound as exc:
        raise not_found(exc) from exc
    except InvalidFindingState as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_finding_state",
                "message": str(exc),
            },
        ) from exc


@router.post(
    "/audits/{audit_id}/findings/{finding_id}/suppress",
    response_model=FindingResponse,
)
def suppress_finding(
    audit_id: str,
    finding_id: str,
    payload: FindingStateChangeRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> FindingResponse:
    return _change_finding_status(
        audit_id,
        finding_id,
        FindingStatus.SUPPRESSED,
        payload,
        request,
        services,
    )


@router.post(
    "/audits/{audit_id}/findings/{finding_id}/accept-risk",
    response_model=FindingResponse,
)
def accept_finding_risk(
    audit_id: str,
    finding_id: str,
    payload: FindingStateChangeRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> FindingResponse:
    return _change_finding_status(
        audit_id,
        finding_id,
        FindingStatus.ACCEPTED_RISK,
        payload,
        request,
        services,
    )


@router.post(
    "/audits/{audit_id}/findings/{finding_id}/reopen",
    response_model=FindingResponse,
)
def reopen_finding(
    audit_id: str,
    finding_id: str,
    payload: FindingStateChangeRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> FindingResponse:
    return _change_finding_status(
        audit_id,
        finding_id,
        FindingStatus.OPEN,
        payload,
        request,
        services,
    )
