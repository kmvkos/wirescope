"""Typed contracts for service-aware protocol audits."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from engine.passive_models import ConfidenceLevel
from inventory.models import AssetRecord, ServiceRecord
from providers.tools import ToolCommand, ToolResult


MAX_OBSERVATION_DATA_BYTES = 12_288
MAX_EVIDENCE_TEXT_BYTES = 256 * 1024
MAX_STRING_VALUE = 2_048
MAX_LIST_ITEMS = 64


class SafetyClass(str, Enum):
    SAFE = "safe"
    GATED = "gated"
    NEVER_DEFAULT = "never-default"


class ProtocolAuditProfile(str, Enum):
    DEFAULT = "default"


class ToolAvailability(BaseModel):
    tool: str
    available: bool
    version: str | None = None
    binary_path: str | None = None
    meets_minimum: bool = True
    message: str = ""


class ServicePredicate(BaseModel):
    model_config = ConfigDict(frozen=True)

    ports: frozenset[int] = Field(default_factory=frozenset)
    protocols: frozenset[str] = Field(default_factory=lambda: frozenset({"tcp"}))
    service_names: frozenset[str] = Field(default_factory=frozenset)
    products: frozenset[str] = Field(default_factory=frozenset)
    tunnels: frozenset[str] = Field(default_factory=frozenset)

    def matches(self, service: ServiceRecord) -> bool:
        if service.protocol.lower() not in {
            item.lower() for item in self.protocols
        }:
            return False
        checks: list[bool] = []
        if self.ports:
            checks.append(service.port in self.ports)
        if self.service_names:
            name = (service.service_name or "").lower()
            checks.append(
                any(
                    token.lower() == name or token.lower() in name
                    for token in self.service_names
                )
            )
        if self.products:
            haystack = " ".join(
                part
                for part in (service.product, service.extra_info, service.banner)
                if part
            ).lower()
            checks.append(
                any(token.lower() in haystack for token in self.products)
            )
        if self.tunnels:
            tunnel = (service.tunnel or "").lower()
            checks.append(
                any(token.lower() == tunnel for token in self.tunnels)
            )
        return any(checks) if checks else False


class ObservationDraft(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    source: str = Field(min_length=1, max_length=64)
    dedupe_key: str = ""


class ProbeTarget(BaseModel):
    asset: AssetRecord
    service: ServiceRecord
    address: str
    port: int = Field(ge=0, le=65_535)
    hostname: str | None = None
    scheme_hint: str | None = None


class ModuleRun(BaseModel):
    module: str
    protocol: str
    tool: str
    available: bool
    skipped: bool = False
    skip_reason: str | None = None
    observation_count: int = 0
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    duration_seconds: float = 0
    evidence_artifact_id: str | None = None
    command_metadata: dict[str, Any] = Field(default_factory=dict)


class ProtocolObservationRecord(BaseModel):
    id: str
    audit_id: str
    asset_id: str
    service_id: str
    protocol: str
    module: str
    kind: str
    data: dict[str, Any]
    confidence: ConfidenceLevel
    source: str
    evidence_artifact_id: str | None
    first_seen: datetime
    last_seen: datetime


class MatchedWork(BaseModel):
    module: str
    target: ProbeTarget


__all__ = [
    "MAX_EVIDENCE_TEXT_BYTES",
    "MAX_OBSERVATION_DATA_BYTES",
    "MatchedWork",
    "ModuleRun",
    "ObservationDraft",
    "ProbeTarget",
    "ProtocolAuditProfile",
    "ProtocolObservationRecord",
    "SafetyClass",
    "ServicePredicate",
    "ToolAvailability",
    "ToolCommand",
    "ToolResult",
]
