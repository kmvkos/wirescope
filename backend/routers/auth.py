from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from auth.models import (
    ChangePasswordRequest,
    LoginRequest,
    SessionUser,
    SessionUserResponse,
)
from auth.service import AuthError
from backend.dependencies import AppServices, get_services
from backend.http import password_change_http_error


router = APIRouter()


def _session_payload(user: SessionUser, services: AppServices) -> SessionUserResponse:
    capabilities = (
        [
            "start_audits",
            "cancel_jobs",
            "manage_findings",
            "generate_reports",
        ]
        if user.can_mutate
        else []
    )
    settings = services.settings
    return SessionUserResponse(
        username=user.username,
        role=user.role,
        capabilities=capabilities,
        policy={
            "passive_duration_min": settings.passive_duration_min,
            "passive_duration_max": settings.passive_duration_max,
            "passive_duration_default": settings.passive_duration_default,
            "listen_duration_min": settings.listen_duration_min,
            "listen_duration_max": settings.listen_duration_max,
            "listen_duration_default": settings.listen_duration_default,
            "listen_max_filesize_kb_default": settings.listen_max_filesize_kb_default,
            "listen_max_filesize_kb_max": settings.listen_max_filesize_kb_max,
            "listen_filter_max_length": settings.listen_filter_max_length,
        },
    )


def _set_session_cookie(
    response: Response,
    token: str,
    services: AppServices,
) -> None:
    settings = services.settings
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="strict",
        secure=settings.session_cookie_secure,
        path="/",
    )


@router.post("/auth/login", response_model=SessionUserResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    services: AppServices = Depends(get_services),
) -> SessionUserResponse:
    # Username is useful operational metadata; passwords and request bodies are
    # never copied into the operational audit log.
    request.state.audit_actor = payload.username
    try:
        user = services.auth.authenticate(payload.username, payload.password)
    except AuthError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    request.state.audit_actor = user.username
    request.state.audit_role = user.role.value
    token = services.auth.create_session(user)
    _set_session_cookie(response, token, services)
    return _session_payload(user, services)


@router.post("/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    services: AppServices = Depends(get_services),
) -> None:
    token = request.cookies.get(services.settings.session_cookie_name)
    current = services.auth.resolve_token(token)
    if current is not None:
        request.state.audit_actor = current.username
        request.state.audit_role = current.role.value
    services.auth.revoke_token(token)
    response.delete_cookie(
        key=services.settings.session_cookie_name,
        path="/",
    )


@router.get("/auth/me", response_model=SessionUserResponse)
def current_user(
    request: Request,
    services: AppServices = Depends(get_services),
) -> SessionUserResponse:
    return _session_payload(request.state.user, services)


@router.post("/auth/password", response_model=SessionUserResponse)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> SessionUserResponse:
    token = request.cookies.get(services.settings.session_cookie_name)
    try:
        user = services.auth.change_password(
            request.state.user,
            payload.current_password,
            payload.new_password,
            keep_token=token,
        )
    except AuthError as exc:
        raise password_change_http_error(exc) from exc
    return _session_payload(user, services)
