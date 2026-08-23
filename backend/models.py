"""Typed HTTP contracts for durable audits and jobs."""

from datetime import datetime
import json
from typing import Any

from pydantic import BaseModel, Field, model_validator

from engine.interfaces import InterfaceInfo
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


class ReadinessResponse(BaseModel):
    status: str
    database: bool
    migrations: bool
    worker: bool
    dependencies: dict[str, bool]


class InterfaceListResponse(BaseModel):
    interfaces: list[InterfaceInfo]
