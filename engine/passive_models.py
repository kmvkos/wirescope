"""Typed contracts shared by passive capture, parsing, sensors, and API."""

from datetime import datetime
from enum import Enum
import re
from typing import Any

from pydantic import BaseModel, Field, computed_field, model_validator

from providers.tools import ToolResult


class PipelineErrorCode(str, Enum):
    INVALID_INTERFACE = "invalid_interface"
    CAPTURE_FAILED = "capture_failed"
    DECODE_FAILED = "decode_failed"
    CANCELLED = "cancelled"
    MALFORMED_INPUT = "malformed_input"
    SENSOR_FAILED = "sensor_failed"
    CLEANUP_FAILED = "cleanup_failed"


class PipelineError(BaseModel):
    code: PipelineErrorCode
    component: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class CaptureStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CaptureResult(BaseModel):
    interface: str
    status: CaptureStatus
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    frame_count: int | None = None
    dropped_packets: int | None = None
    pcap_path: str | None = None
    pcap_reference: str | None = None
    retained: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[PipelineError] = Field(default_factory=list)
    tool_result: ToolResult


class EvidenceReference(BaseModel):
    reference: str
    frame_number: int | None = None


class ObservationMetadata(BaseModel):
    sensor: str
    timestamp: datetime | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    evidence: EvidenceReference


class Observation(BaseModel):
    kind: str
    metadata: ObservationMetadata
    data: dict[str, Any] = Field(default_factory=dict)


class SensorStatus(str, Enum):
    ABSENT = "absent"
    DETECTED = "detected"
    PARTIAL = "partial"
    ERROR = "error"


class SensorResult(BaseModel):
    name: str
    status: SensorStatus
    hits: int = Field(default=0, ge=0)
    observations: list[Observation] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[PipelineError] = Field(default_factory=list)

    @computed_field
    @property
    def detected(self) -> bool:
        return self.status in {
            SensorStatus.DETECTED,
            SensorStatus.PARTIAL,
        }

    @model_validator(mode="after")
    def validate_state(self) -> "SensorResult":
        if self.status == SensorStatus.ABSENT and (
            self.observations or self.errors
        ):
            raise ValueError("absent sensors cannot contain observations/errors")
        if self.status == SensorStatus.DETECTED and self.errors:
            raise ValueError("detected sensors with errors must be partial")
        if self.status == SensorStatus.ERROR and not self.errors:
            raise ValueError("error sensors must contain an error")
        return self


def _field_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


class PacketRecord(BaseModel):
    frame_number: int
    timestamp: datetime | None = None
    protocols: list[str] = Field(default_factory=list)
    source_mac: str | None = None
    destination_mac: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    fields: dict[str, list[str]] = Field(default_factory=dict)

    def values(self, *aliases: str) -> list[str]:
        alias_tokens = [_field_token(alias) for alias in aliases]
        values: list[str] = []
        for name, field_values in self.fields.items():
            name_token = _field_token(name)
            if any(
                name_token == alias or name_token.endswith(alias)
                for alias in alias_tokens
            ):
                for value in field_values:
                    if value not in values:
                        values.append(value)
        return values

    def first(self, *aliases: str) -> str | None:
        values = self.values(*aliases)
        return values[0] if values else None

    def has_protocol(self, *protocols: str) -> bool:
        protocol_set = {protocol.lower() for protocol in self.protocols}
        return any(protocol.lower() in protocol_set for protocol in protocols)


class PacketDataset(BaseModel):
    packets: list[PacketRecord] = Field(default_factory=list)
    errors: list[PipelineError] = Field(default_factory=list)
    decode_result: ToolResult
    decode_reference: str | None = None


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HINT = "hint"
    UNKNOWN = "unknown"


class AssessmentConclusion(BaseModel):
    value: Any
    confidence: ConfidenceLevel
    rationale: str
    sources: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PassiveAssessment(BaseModel):
    visibility: AssessmentConclusion
    layer2: dict[str, Any] = Field(default_factory=dict)
    ipv4: dict[str, Any] = Field(default_factory=dict)
    ipv6: dict[str, Any] = Field(default_factory=dict)
    infrastructure: list[AssessmentConclusion] = Field(default_factory=list)


class PassiveMetrics(BaseModel):
    capture_subprocesses: int = Field(default=0, ge=0)
    decode_subprocesses: int = Field(default=0, ge=0)

    @computed_field
    @property
    def total_subprocesses(self) -> int:
        return self.capture_subprocesses + self.decode_subprocesses


class PassiveResult(BaseModel):
    schema_version: str = "1.0"
    interface: str
    requested_duration_seconds: int
    capture: CaptureResult
    sensors: dict[str, SensorResult]
    assessment: PassiveAssessment
    errors: list[PipelineError] = Field(default_factory=list)
    metrics: PassiveMetrics
