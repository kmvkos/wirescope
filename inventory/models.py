"""Typed asset, address, name, service, and inventory contracts."""

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

from engine.passive_models import ConfidenceLevel
from engine.scope import ActiveProfile


class AssetState(str, Enum):
    OBSERVED = "observed"
    RESPONSIVE = "responsive"
    UNRESPONSIVE = "unresponsive"
    UNKNOWN = "unknown"


class DeviceClassHint(str, Enum):
    SERVER = "server-like"
    WORKSTATION = "workstation-like"
    NETWORK_DEVICE = "network-device-like"
    PRINTER = "printer-like"
    IOT = "iot-like"
    UNKNOWN = "unknown"


class ConfirmedScopeRecord(BaseModel):
    id: str
    audit_id: str
    created_at: datetime
    activated_at: datetime | None
    profile: ActiveProfile
    interface: str
    targets: list[str]
    address_families: list[int]
    address_count: int
    route_context: dict[str, Any]
    timing_policy: str
    actor: str | None
    snapshot_hash: str


class AssetAddressRecord(BaseModel):
    id: str
    asset_id: str
    address: str
    family: int
    is_primary: bool
    first_seen: datetime
    last_seen: datetime
    source: str
    confidence: ConfidenceLevel


class AssetNameRecord(BaseModel):
    id: str
    asset_id: str
    name: str
    name_type: str
    source: str
    confidence: ConfidenceLevel
    first_seen: datetime
    last_seen: datetime


class ServiceRecord(BaseModel):
    id: str
    audit_id: str
    asset_id: str
    protocol: str
    port: int = Field(ge=0, le=65_535)
    state: str
    reason: str | None
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    tunnel: str | None
    cpe: list[str]
    banner: str | None
    method: str | None
    confidence: ConfidenceLevel
    source: str
    first_seen: datetime
    last_seen: datetime


class AssetRecord(BaseModel):
    id: str
    audit_id: str
    state: AssetState
    mac: str | None
    vendor: str | None
    vendor_source: str | None
    vendor_database_version: str | None
    device_class_hint: DeviceClassHint
    device_class_confidence: ConfidenceLevel
    os_family: str | None
    os_name: str | None
    os_generation: str | None
    os_accuracy: int | None
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any]
    addresses: list[AssetAddressRecord] = Field(default_factory=list)
    names: list[AssetNameRecord] = Field(default_factory=list)
    services: list[ServiceRecord] = Field(default_factory=list)


class InventorySummary(BaseModel):
    assets: int = 0
    services: int = 0
    tcp_services: int = 0
    udp_services: int = 0
    ipv4_addresses: int = 0
    ipv6_addresses: int = 0
    device_classes: dict[str, int] = Field(default_factory=dict)


ItemT = TypeVar("ItemT")


class InventoryPage(BaseModel, Generic[ItemT]):
    items: list[ItemT]
    limit: int
    offset: int
    total: int
