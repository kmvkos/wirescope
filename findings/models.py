"""Versioned finding, severity, and evaluation contracts."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from engine.passive_models import ConfidenceLevel
from inventory.models import AssetRecord, ServiceRecord
from protocol_audits.models import ProtocolObservationRecord


FINDING_SCHEMA_VERSION = 1
MAX_FINDING_DATA_BYTES = 12_288
MAX_TITLE = 256
MAX_TEXT = 4_096
MAX_DEDUPE_KEY = 128
MAX_OBSERVATION_LINKS = 64

NON_EVIDENCE_KINDS = frozenset(
    {
        "cancelled",
        "tool_timeout",
        "tool_unavailable",
        "empty_output",
        "tool_failed",
        "malformed_output",
        "dns_unreachable",
    }
)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

CONFIDENCE_RANK = {
    ConfidenceLevel.CONFIRMED: 0,
    ConfidenceLevel.HIGH: 1,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.LOW: 3,
    ConfidenceLevel.HINT: 4,
    ConfidenceLevel.UNKNOWN: 5,
}


class FindingStatus(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


class FindingDraft(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1, max_length=64)
    rule_version: str = Field(min_length=1, max_length=16)
    family: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=MAX_TITLE)
    severity: Severity
    confidence: ConfidenceLevel
    asset_id: str | None = None
    service_id: str | None = None
    description: str = Field(min_length=1, max_length=MAX_TEXT)
    rationale: str = Field(min_length=1, max_length=MAX_TEXT)
    recommendation: str = Field(min_length=1, max_length=MAX_TEXT)
    data: dict[str, Any] = Field(default_factory=dict)
    observation_ids: list[str] = Field(default_factory=list)
    evidence_artifact_ids: list[str] = Field(default_factory=list)
    dedupe_key: str = Field(min_length=1, max_length=MAX_DEDUPE_KEY)


class FindingStateEventRecord(BaseModel):
    id: int
    finding_id: str
    audit_id: str
    created_at: datetime
    actor: str
    from_status: FindingStatus
    to_status: FindingStatus
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class FindingRecord(BaseModel):
    id: str
    audit_id: str
    asset_id: str | None
    service_id: str | None
    rule_id: str
    rule_version: str
    schema_version: int
    family: str
    title: str
    severity: Severity
    confidence: ConfidenceLevel
    status: FindingStatus
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
    state_events: list[FindingStateEventRecord] = Field(default_factory=list)


class EvaluationContext(BaseModel):
    audit_id: str
    observations: list[ProtocolObservationRecord] = Field(default_factory=list)
    services: list[ServiceRecord] = Field(default_factory=list)
    assets: list[AssetRecord] = Field(default_factory=list)
    passive_result: dict[str, Any] | None = None
    passive_artifact_id: str | None = None
    evaluated_at: datetime


__all__ = [
    "CONFIDENCE_RANK",
    "EvaluationContext",
    "FINDING_SCHEMA_VERSION",
    "FindingDraft",
    "FindingRecord",
    "FindingStateEventRecord",
    "FindingStatus",
    "MAX_DEDUPE_KEY",
    "MAX_FINDING_DATA_BYTES",
    "MAX_OBSERVATION_LINKS",
    "MAX_TEXT",
    "MAX_TITLE",
    "NON_EVIDENCE_KINDS",
    "SEVERITY_RANK",
    "Severity",
]
