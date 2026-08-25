"""Typed durable job domain contracts."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field, field_validator


def _as_utc(value: Any) -> Any:
    """SQLite may return timezone-aware columns as naive UTC datetimes.

    Persisted WireScope timestamps are UTC. Re-attaching UTC at the domain
    boundary makes API JSON unambiguous (``Z``/``+00:00``) instead of letting
    browsers interpret a naive UTC clock value as local time.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


class UtcModel(BaseModel):
    @field_validator("*", mode="before")
    @classmethod
    def normalize_datetime_fields(cls, value: Any) -> Any:
        return _as_utc(value)


class AuditStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"

    @property
    def terminal(self) -> bool:
        return self in {
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.INTERRUPTED,
        }


class ErrorCategory(str, Enum):
    VALIDATION = "validation"
    TOOL_MISSING = "tool_missing"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INTERNAL = "internal"
    STORAGE = "storage"
    PARSE = "parse"


class RetentionClass(str, Enum):
    TEMPORARY = "temporary"
    AUDIT = "audit"
    DEBUG = "debug"
    REPORT = "report"


class JobError(UtcModel):
    code: str
    category: ErrorCategory
    message: str
    component: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class JobProgress(UtcModel):
    percentage: int = Field(ge=0, le=100)
    stage: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=512)


class AuditRecord(UtcModel):
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


class JobRecord(UtcModel):
    id: str
    audit_id: str
    type: str
    status: JobStatus
    priority: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime | None = None
    progress: int
    stage: str
    message: str | None
    target: str | None
    parameters: dict[str, Any]
    result_reference: str | None
    cancel_requested: bool
    worker_id: str | None
    attempt: int
    resource_key: str | None
    resource_group: str | None = None
    error: JobError | None

    @property
    def result_available(self) -> bool:
        return self.result_reference is not None


class JobEventRecord(UtcModel):
    id: int
    audit_id: str
    job_id: str
    created_at: datetime
    event_type: str
    stage: str | None
    progress: int | None
    message: str
    details: dict[str, Any]


class ArtifactRecord(UtcModel):
    id: str
    audit_id: str
    job_id: str | None
    artifact_type: str
    relative_path: str
    content_type: str
    size: int
    sha256: str
    created_at: datetime
    retention_class: RetentionClass
    schema_name: str | None
    schema_version: int | None


RecordT = TypeVar("RecordT")


class Page(BaseModel, Generic[RecordT]):
    items: list[RecordT]
    limit: int
    offset: int
    total: int
