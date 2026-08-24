from __future__ import annotations

import shutil
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from appliance.netctl import ApplySpec, NetctlError
from backend.dependencies import AppServices, get_services
from backend.http import interface_http_error, netctl_http_error
from backend.models import (
    HealthResponse,
    InterfaceListResponse,
    NetworkApplyRequest,
    ReadinessResponse,
)
from engine.interfaces import InterfaceValidationError
from engine.network import NetworkConfirmRequired
from engine.scope import ScopeProposal, ScopeValidator
from persistence.schema import migrations_current


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
@router.get("/status", response_model=HealthResponse)
def health(services: AppServices = Depends(get_services)) -> HealthResponse:
    settings = services.settings
    return HealthResponse(
        status="ok",
        product=settings.app_name,
        version=settings.app_version,
        cookie_secure=settings.session_cookie_secure,
        trust_proxy=settings.trust_proxy,
        tls=settings.tls_enabled,
    )


@router.get("/ready", response_model=ReadinessResponse)
def ready(services: AppServices = Depends(get_services)) -> ReadinessResponse:
    settings = services.settings
    database_ready = services.database.is_accessible()
    migration_ready = database_ready and migrations_current(
        services.database,
        settings.project_root,
    )
    worker_ready = migration_ready and services.jobs.worker_is_ready(
        settings.worker_stale_after_seconds
    )
    dependencies = {
        "dumpcap": shutil.which(settings.dumpcap_binary) is not None,
        "tshark": shutil.which(settings.tshark_binary) is not None,
        "nmap": shutil.which(settings.nmap_binary) is not None,
    }
    ready_state = (
        database_ready
        and migration_ready
        and worker_ready
        and all(dependencies.values())
    )
    response = ReadinessResponse(
        status="ready" if ready_state else "not_ready",
        database=database_ready,
        migrations=migration_ready,
        worker=worker_ready,
        dependencies=dependencies,
    )
    if not ready_state:
        raise HTTPException(
            status_code=503,
            detail=response.model_dump(mode="json"),
        )
    return response


@router.get("/environment")
def environment(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.environment_provider()


@router.get("/interfaces", response_model=InterfaceListResponse)
def interfaces(services: AppServices = Depends(get_services)) -> InterfaceListResponse:
    try:
        discovery = services.interfaces.discover()
    except InterfaceValidationError as exc:
        raise interface_http_error(exc) from exc
    return InterfaceListResponse(interfaces=discovery.interfaces)


@router.get("/network/interfaces")
def network_interfaces(
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    try:
        return services.network.list_payload()
    except Exception as exc:
        if isinstance(exc, NetctlError):
            raise netctl_http_error(exc) from exc
        raise


@router.post("/network/interfaces/{name}")
def network_apply(
    name: str,
    payload: NetworkApplyRequest,
    request: Request,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    client_host = request.client.host if request.client is not None else None
    spec = ApplySpec(
        interface=name,
        role=payload.role,
        method=payload.method,
        address=payload.address,
        gateway=payload.gateway,
        dns=tuple(payload.dns),
        confirm=payload.confirm,
        bind_host=services.settings.bind_host,
    )
    try:
        return services.network.apply(spec, client_host=client_host)
    except NetworkConfirmRequired as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": exc.code,
                "message": exc.message,
                "reasons": exc.reasons,
                "remaining_ipv4": exc.remaining_ipv4,
            },
        ) from exc
    except NetctlError as exc:
        raise netctl_http_error(exc) from exc


@router.get("/scope/proposal", response_model=ScopeProposal)
def scope_proposal(
    interface: str = Query(min_length=1, max_length=64),
    services: AppServices = Depends(get_services),
) -> ScopeProposal:
    try:
        discovery = services.interfaces.discover()
    except InterfaceValidationError as exc:
        raise interface_http_error(exc) from exc
    selected = next(
        (item for item in discovery.interfaces if item.name == interface),
        None,
    )
    if selected is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "unknown_interface",
                "message": f"Unknown network interface: {interface}",
            },
        )
    environment = services.environment_provider() or {}
    peers = [
        {
            "name": item.name,
            "ipv4": list(item.ipv4),
            "ipv6": list(item.ipv6),
        }
        for item in discovery.interfaces
    ]
    if not any(peer["name"] == selected.name for peer in peers):
        peers.append(
            {
                "name": selected.name,
                "ipv4": list(selected.ipv4),
                "ipv6": list(selected.ipv6),
            }
        )
    known = {peer["name"] for peer in peers}
    for item in environment.get("interfaces") or []:
        name = str(item.get("name") or "")
        if not name or name in known:
            continue
        peers.append(
            {
                "name": name,
                "ipv4": list(item.get("ipv4") or []),
                "ipv6": list(item.get("ipv6") or []),
            }
        )
    return ScopeValidator(services.settings).propose(
        interface_name=selected.name,
        assigned=[*selected.ipv4, *selected.ipv6],
        peers=peers,
        routes=list(environment.get("routes") or []),
    )
