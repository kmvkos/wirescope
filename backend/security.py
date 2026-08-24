from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from auth.models import Role
from backend.dependencies import AppServices, get_services


def normalized_api_path(path: str) -> str:
    if path == "/api/v1":
        return "/api"
    if path.startswith("/api/v1/"):
        return "/api/" + path[len("/api/v1/") :]
    return path


def is_public_request(request: Request) -> bool:
    path = normalized_api_path(request.url.path)
    method = request.method.upper()
    if method == "OPTIONS":
        return True
    if path == "/" or path.startswith("/static/"):
        return True
    if path in {"/docs", "/redoc", "/openapi.json"}:
        return True
    if method == "GET" and path in {
        "/api/health",
        "/api/status",
        "/api/ready",
    }:
        return True
    if method == "POST" and path in {"/api/auth/login", "/api/auth/logout"}:
        return True
    return False


def requires_auditor(request: Request) -> bool:
    path = normalized_api_path(request.url.path)
    if path == "/api/auth/password":
        return False
    if path == "/api/network" or path.startswith("/api/network/"):
        return True
    return request.method.upper() not in {"GET", "HEAD", "OPTIONS"}


def auth_guard(
    request: Request,
    services: AppServices = Depends(get_services),
) -> None:
    if is_public_request(request):
        return
    token = request.cookies.get(services.settings.session_cookie_name)
    user = services.auth.resolve_token(token)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "unauthenticated",
                "message": "Sign in required",
            },
        )
    if requires_auditor(request) and user.role is not Role.AUDITOR:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "forbidden_role",
                "message": "Viewer cannot start or cancel audits",
            },
        )
    request.state.user = user
