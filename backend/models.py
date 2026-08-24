"""Typed HTTP contracts for durable audits and jobs."""

from datetime import datetime
import json
from typing import Any

from pydantic import BaseModel, Field, model_validator

from engine.interfaces import InterfaceInfo
from engine.scope import ActiveProfile
from inventory.models import (
    AssetRecord,
    InventorySummary,
    ServiceRecord,
)
from jobs.models import AuditStatus, JobError, JobStatus


class CreateAuditRequest(BaseModel):
    profile: str = Field(default="passive", min_length=1, max_length=64)
    interface: str = Field(min_length=1, max_length=64)
    scope: dict[str, Any] = Field(default_factory=dict)
    actor: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_scope_size(self) -> "CreateAuditRequest":
        if len(json.dumps(self.scope, default=str).encode("utf-8")) > 16_384:
            raise ValueError("scope exceeds the 16 KiB limit")
        return self


class PassiveJobRequest(BaseModel):
    duration_seconds: int | None = None
    priority: int = Field(default=0, ge=-100, le=100)


class CaptureJobRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    duration_seconds: int | None = Field(default=None, ge=0, le=21_600)
    max_filesize_kb: int | None = Field(default=None, ge=1, le=1_048_576)
    filter: str | None = Field(default=None, max_length=1024)
    priority: int = Field(default=0, ge=-100, le=100)


class DiscoveryJobRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    scope: list[str] = Field(min_length=1, max_length=256)
    profile: ActiveProfile = ActiveProfile.STANDARD
    priority: int = Field(default=0, ge=-100, le=100)


class AuditResponse(BaseModel):
    id: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    status: AuditStatus
    profile: str
    interface: str | None
    scope: dict[str, Any]
    actor: str | None
    environment_snapshot_reference: str | None
    summary: dict[str, Any]
    error: dict[str, Any] | None


class JobResponse(BaseModel):
    id: str
    audit_id: str
    type: str
    status: JobStatus
    priority: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime | None = None
    progress: int = Field(ge=0, le=100)
    stage: str
    message: str | None
    target: str | None
    cancel_requested: bool
    attempt: int
    error: JobError | None
    result_available: bool
    result_url: str | None


class JobAcceptedResponse(BaseModel):
    audit_id: str
    job_id: str
    status: JobStatus
    status_url: str


class AuditPageResponse(BaseModel):
    items: list[AuditResponse]
    limit: int
    offset: int
    total: int


class JobPageResponse(BaseModel):
    items: list[JobResponse]
    limit: int
    offset: int
    total: int


class CaptureSessionResponse(BaseModel):
    job_id: str
    audit_id: str
    status: JobStatus
    interface: str
    filter: str | None
    duration_seconds: int | None
    max_filesize_kb: int | None
    promiscuous: bool = True
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress: int = Field(ge=0, le=100)
    stage: str
    message: str | None
    frame_count: int | None = None
    byte_count: int | None = None
    pcap_bytes: int | None = None
    pcap_url: str | None = None
    result_available: bool = False
    cancel_requested: bool = False
    error: JobError | None = None


class CaptureSessionPageResponse(BaseModel):
    items: list[CaptureSessionResponse]
    limit: int
    offset: int
    total: int


class JobEventResponse(BaseModel):
    id: int
    audit_id: str
    job_id: str
    created_at: datetime
    event_type: str
    stage: str | None
    progress: int | None
    message: str
    details: dict[str, Any]


class JobEventPageResponse(BaseModel):
    items: list[JobEventResponse]
    limit: int
    offset: int
    total: int


class HealthResponse(BaseModel):
    status: str
    product: str
    version: str
    cookie_secure: bool = False
    trust_proxy: bool = False
    tls: bool = False


class ReadinessResponse(BaseModel):
    status: str
    database: bool
    migrations: bool
    worker: bool
    dependencies: dict[str, bool]


class InterfaceListResponse(BaseModel):
    interfaces: list[InterfaceInfo]


class NetworkApplyRequest(BaseModel):
    role: str = Field(min_length=1, max_length=16)
    method: str = Field(min_length=1, max_length=16)
    address: str | None = Field(default=None, max_length=64)
    gateway: str | None = Field(default=None, max_length=64)
    dns: list[str] = Field(default_factory=list, max_length=8)
    confirm: bool = False

    @model_validator(mode="after")
    def validate_network_apply(self) -> "NetworkApplyRequest":
        if self.role not in {"management", "capture"}:
            raise ValueError("role must be management or capture")
        if self.method not in {"dhcp", "static", "none"}:
            raise ValueError("method must be dhcp, static, or none")
        if self.method == "static" and not (self.address or "").strip():
            raise ValueError("static method requires address")
        cleaned: list[str] = []
        for item in self.dns:
            value = item.strip()
            if value:
                cleaned.append(value)
        self.dns = cleaned
        return self


class AssetPageResponse(BaseModel):
    items: list[AssetRecord]
    limit: int
    offset: int
    total: int


class ServicePageResponse(BaseModel):
    items: list[ServiceRecord]
    limit: int
    offset: int
    total: int


class InventorySummaryResponse(InventorySummary):
    pass


class ProtocolAuditRequest(BaseModel):
    profile: str = "default"
    modules: list[str] | None = Field(default=None, max_length=32)
    priority: int = Field(default=0, ge=-100, le=100)

    @model_validator(mode="after")
    def validate_modules(self) -> "ProtocolAuditRequest":
        if self.profile != "default":
            raise ValueError("Only the default protocol-audit profile is available")
        if self.modules is not None:
            if not self.modules:
                raise ValueError("modules must not be empty when provided")
            for name in self.modules:
                if not name or len(name) > 32 or not name.replace("-", "").isalnum():
                    raise ValueError(f"Invalid protocol module name: {name}")
                if name != name.lower():
                    raise ValueError("Protocol module names must be lowercase")
        return self


class ProtocolObservationResponse(BaseModel):
    id: str
    audit_id: str
    asset_id: str
    service_id: str
    protocol: str
    module: str
    kind: str
    data: dict[str, Any]
    confidence: str
    source: str
    evidence_artifact_id: str | None
    first_seen: datetime
    last_seen: datetime


class ObservationPageResponse(BaseModel):
    items: list[ProtocolObservationResponse]
    limit: int
    offset: int
    total: int


class FindingsJobRequest(BaseModel):
    priority: int = Field(default=0, ge=-100, le=100)


class FindingStateChangeRequest(BaseModel):
    actor: str | None = Field(default=None, max_length=128)
    reason: str = Field(min_length=1, max_length=512)


class FindingStateEventResponse(BaseModel):
    id: int
    finding_id: str
    audit_id: str
    created_at: datetime
    actor: str
    from_status: str
    to_status: str
    reason: str
    details: dict[str, Any]


class FindingResponse(BaseModel):
    id: str
    audit_id: str
    asset_id: str | None
    service_id: str | None
    rule_id: str
    rule_version: str
    schema_version: int
    family: str
    title: str
    severity: str
    confidence: str
    status: str
    description: str
    rationale: str
    recommendation: str
    data: dict[str, Any]
    observation_ids: list[str]
    evidence_artifact_ids: list[str]
    dedupe_key: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    state_events: list[FindingStateEventResponse] = Field(default_factory=list)


class FindingPageResponse(BaseModel):
    items: list[FindingResponse]
    limit: int
    offset: int
    total: int


class ReportJobRequest(BaseModel):
    actor: str | None = Field(default=None, max_length=128)
    priority: int = Field(default=0, ge=-100, le=100)


class ReportResponse(BaseModel):
    id: str
    audit_id: str
    job_id: str | None
    schema_name: str
    schema_version: int
    generated_at: datetime
    actor: str | None
    source_hash: str
    summary: dict[str, Any]
    json_artifact_id: str
    html_artifact_id: str
    created_at: datetime
    json_url: str
    html_url: str


class ReportPageResponse(BaseModel):
    items: list[ReportResponse]
    limit: int
    offset: int
    total: int

