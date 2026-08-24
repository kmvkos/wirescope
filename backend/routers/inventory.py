from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import AppServices, get_services
from backend.http import not_found
from backend.models import (
    AssetPageResponse,
    InventorySummaryResponse,
    ServicePageResponse,
)
from inventory.models import AssetRecord, AssetState, DeviceClassHint
from jobs.service import EntityNotFound


router = APIRouter()


@router.get("/audits/{audit_id}/assets", response_model=AssetPageResponse)
def list_assets(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    address: str | None = None,
    hostname: str | None = None,
    mac: str | None = None,
    vendor: str | None = None,
    state: AssetState | None = None,
    device_class: DeviceClassHint | None = None,
    services: AppServices = Depends(get_services),
) -> AssetPageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    page = services.inventory.list_assets(
        audit_id=audit_id,
        limit=limit,
        offset=offset,
        address=address,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        state=state,
        device_class=device_class,
    )
    return AssetPageResponse(
        items=page.items,
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get("/audits/{audit_id}/assets/{asset_id}", response_model=AssetRecord)
def get_asset(
    audit_id: str,
    asset_id: str,
    services: AppServices = Depends(get_services),
) -> AssetRecord:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    asset = services.inventory.get_asset(audit_id, asset_id)
    if asset is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "not_found",
                "message": f"Asset not found: {asset_id}",
            },
        )
    return asset


@router.get("/audits/{audit_id}/services", response_model=ServicePageResponse)
def list_services(
    audit_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    asset_id: str | None = None,
    protocol: str | None = None,
    port: int | None = Query(default=None, ge=0, le=65_535),
    state: str | None = None,
    service_name: str | None = None,
    product: str | None = None,
    services: AppServices = Depends(get_services),
) -> ServicePageResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc

    page = services.inventory.list_services(
        audit_id=audit_id,
        limit=limit,
        offset=offset,
        asset_id=asset_id,
        protocol=protocol,
        port=port,
        state=state,
        service_name=service_name,
        product=product,
    )
    return ServicePageResponse(
        items=page.items,
        limit=page.limit,
        offset=page.offset,
        total=page.total,
    )


@router.get(
    "/audits/{audit_id}/inventory",
    response_model=InventorySummaryResponse,
)
def inventory_summary(
    audit_id: str,
    services: AppServices = Depends(get_services),
) -> InventorySummaryResponse:
    try:
        services.jobs.get_audit(audit_id)
    except EntityNotFound as exc:
        raise not_found(exc) from exc
    return InventorySummaryResponse(
        **services.inventory.summary(audit_id).model_dump()
    )
