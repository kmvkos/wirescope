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
    source_origin: str = "captured"
    original_filename: str | None = None
    capture_format: str | None = None
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
    interface: str = Field(min_length=1, max_length=64)
    method: str = Field(pattern="^(dhcp|static|none)$")
    role: str = Field(default="management", pattern="^(management|capture)$")
    address: str | None = Field(default=None, max_length=64)
    gateway: str | None = Field(default=None, max_length=64)
    dns: list[str] = Field(default_factory=list, max_length=4)


class NetworkApplyResponse(BaseModel):
    interface: str
    method: str
    role: str
    addresses: list[str]
    gateway: str | None
    dns: list[str]
    access_urls: list[str]
    connectivity_note: str
    warnings: list[str]


class ScopeProposalResponse(BaseModel):
    interface: str
    source: str
    canonical_targets: list[str]
    displayed_targets: list[str]
    rejected_targets: list[str]
    confidence: str
    warnings: list[str]
    vlan_ids: list[int]
    topology_hints: dict[str, Any] = Field(default_factory=dict)


class ScopeConfirmationRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    targets: list[str] = Field(min_length=1, max_length=256)
    profile: ActiveProfile
    confirmed: bool


class ScopeConfirmationResponse(BaseModel):
    audit_id: str
    interface: str
    targets: list[str]
    profile: ActiveProfile
    confirmed: bool
    confirmation_id: str
    created_at: datetime


class ProtocolJobRequest(BaseModel):
    modules: list[str] | None = Field(default=None, max_length=64)
    priority: int = Field(default=0, ge=-100, le=100)


class FindingJobRequest(BaseModel):
    priority: int = Field(default=0, ge=-100, le=100)


class ReportJobRequest(BaseModel):
    priority: int = Field(default=0, ge=-100, le=100)


class FindingResponse(BaseModel):
    id: str
    audit_id: str
    asset_id: str | None
    service_id: str | None
    rule_id: str
    status: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    state_events: list[dict[str, Any]] = Field(default_factory=list)


class FindingPageResponse(BaseModel):
    items: list[FindingResponse]
    limit: int
    offset: int
    total: int


class FindingStateRequest(BaseModel):
    status: str = Field(pattern="^(open|accepted|resolved|false_positive)$")
    note: str | None = Field(default=None, max_length=2048)


class ReportResponse(BaseModel):
    id: str
    audit_id: str
    job_id: str
    created_at: datetime
    summary: dict[str, Any]
    json_artifact_id: str
    html_artifact_id: str
    json_url: str
    html_url: str
