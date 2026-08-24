"""Versioned audit-report view model.

The report is assembled from persisted audit, inventory, findings, and
artifact metadata. It never embeds raw provider stdout or filesystem paths.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from findings.models import FindingStatus, Severity


REPORT_SCHEMA = "audit-report"
REPORT_SCHEMA_VERSION = 1
REPORT_INPUT_LIMIT = 10_000
MAX_HEADLINE = 256

REPORT_JSON_ARTIFACT = "audit_report_json"
REPORT_HTML_ARTIFACT = "audit_report_html"
REPORT_RESULT_ARTIFACT = "report_result"

EXCLUDED_EVIDENCE_TYPES = frozenset(
    {
        REPORT_JSON_ARTIFACT,
        REPORT_HTML_ARTIFACT,
        REPORT_RESULT_ARTIFACT,
    }
)


class ReportAuditMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    status: str
    profile: str
    interface: str | None = None
    actor: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class ReportEnvironmentInterface(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    state: str | None = None
    mac: str | None = None
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)


class ReportEnvironment(BaseModel):
    model_config = ConfigDict(frozen=True)

    hostname: str | None = None
    capture_interface: str | None = None
    had_l3_address: bool | None = None
    interfaces: list[ReportEnvironmentInterface] = Field(default_factory=list)
    default_route: dict[str, str | None] | None = None
    dns: list[str] = Field(default_factory=list)


class ReportNeighbor(BaseModel):
    model_config = ConfigDict(frozen=True)

    protocol: str
    name: str | None = None
    port_id: str | None = None
    native_vlan: int | None = None
    voice_vlan: int | None = None
    pvid: int | None = None


class ReportStpSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    bpdus_observed: int = 0
    root_bridge_ids: list[str] = Field(default_factory=list)
    bridge_ids: list[str] = Field(default_factory=list)


class ReportDhcpSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    observed: bool = False
    server_count: int = 0
    servers: list[str] = Field(default_factory=list)
    routers: list[str] = Field(default_factory=list)
    subnet_masks: list[str] = Field(default_factory=list)


class ReportNamingSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: str
    hits: int = 0
    names: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)


class ReportPassive(BaseModel):
    """Bounded view of the stored passive capture and assessment."""

    model_config = ConfigDict(frozen=True)

    available: bool = False
    capture_interface: str | None = None
    capture_interface_state: str | None = None
    capture_mac: str | None = None
    capture_ipv4: list[str] = Field(default_factory=list)
    capture_ipv6: list[str] = Field(default_factory=list)
    had_l3_address: bool | None = None
    duration_seconds: float | None = None
    frame_count: int | None = None
    visibility: str | None = None
    visibility_rationale: str | None = None
    segment_status: str = "unknown"
    segment_note: str = "No passive capture is stored for this audit"
    tagged_vlan_ids: list[int] = Field(default_factory=list)
    tagged_frame_count: int = 0
    untagged_traffic_observed: bool = False
    port_type_hint: str | None = None
    vlan_tag_note: str
    neighbors: list[ReportNeighbor] = Field(default_factory=list)
    stp: ReportStpSummary = Field(default_factory=ReportStpSummary)
    arp_host_count: int = 0
    arp_bindings: list[dict[str, str]] = Field(default_factory=list)
    dhcp: ReportDhcpSummary = Field(default_factory=ReportDhcpSummary)
    naming: list[ReportNamingSummary] = Field(default_factory=list)
    detected_sensors: list[str] = Field(default_factory=list)


class ReportScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    confirmed: bool
    audit_scope: dict[str, Any] = Field(default_factory=dict)
    profile: str | None = None
    interface: str | None = None
    targets: list[str] = Field(default_factory=list)
    address_count: int | None = None
    address_families: list[int] = Field(default_factory=list)
    timing_policy: str | None = None
    snapshot_hash: str | None = None


class ReportAsset(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    state: str
    mac: str | None = None
    vendor: str | None = None
    device_class_hint: str
    os_name: str | None = None
    addresses: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)


class ReportService(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    asset_id: str
    protocol: str
    port: int
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    tunnel: str | None = None


class ReportFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    rule_id: str
    rule_version: str
    family: str
    title: str
    severity: str
    confidence: str
    status: str
    asset_id: str | None = None
    service_id: str | None = None
    description: str
    rationale: str
    recommendation: str
    observation_ids: list[str] = Field(default_factory=list)
    evidence_artifact_ids: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class ReportRecommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    severity: str
    recommendation: str
    finding_ids: list[str] = Field(default_factory=list)
    affected_asset_ids: list[str] = Field(default_factory=list)


class ReportEvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    artifact_type: str
    content_type: str
    size: int
    sha256: str
    schema_name: str | None = None
    schema_version: int | None = None
    created_at: datetime


class ExecutiveSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    headline: str = Field(min_length=1, max_length=MAX_HEADLINE)
    asset_count: int
    service_count: int
    finding_count: int
    open_finding_count: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    highest_open_severity: str | None = None
    confirmed_scope: bool
    detected_sensors: list[str] = Field(default_factory=list)
    frame_count: int | None = None
    had_l3_address: bool | None = None
    tagged_vlan_ids: list[int] = Field(default_factory=list)
    segment_status: str = "unknown"
    segment_note: str = "No passive capture is stored for this audit"


class ReportMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    product: str
    version: str
    job_id: str | None = None
    actor: str | None = None
    raw_provider_output_excluded: bool = True
    truncated: bool = False
    input_limits: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    """Canonical versioned report document persisted as JSON."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_name: Literal["audit-report"] = Field(
        default=REPORT_SCHEMA,
        alias="schema",
        serialization_alias="schema",
    )
    schema_version: Literal[1] = REPORT_SCHEMA_VERSION
    report_id: str
    generated_at: datetime
    source_hash: str
    audit: ReportAuditMetadata
    executive_summary: ExecutiveSummary
    environment: ReportEnvironment
    passive: ReportPassive
    scope: ReportScope
    assets: list[ReportAsset] = Field(default_factory=list)
    services: list[ReportService] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    recommendations: list[ReportRecommendation] = Field(default_factory=list)
    evidence_references: list[ReportEvidenceReference] = Field(
        default_factory=list
    )
    metadata: ReportMetadata

    def to_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ReportRecord(BaseModel):
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


class ReportSource(BaseModel):
    """Normalized inputs collected from persisted stores. Not an export."""

    audit_id: str
    audit_status: str
    audit_profile: str
    audit_interface: str | None = None
    audit_actor: str | None = None
    audit_created_at: datetime
    audit_started_at: datetime | None = None
    audit_finished_at: datetime | None = None
    audit_summary: dict[str, Any] = Field(default_factory=dict)
    audit_scope: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] | None = None
    confirmed_scope: dict[str, Any] | None = None
    assets: list[ReportAsset] = Field(default_factory=list)
    services: list[ReportService] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    evidence_references: list[ReportEvidenceReference] = Field(
        default_factory=list
    )
    detected_sensors: list[str] = Field(default_factory=list)
    passive_result: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
    truncated: bool = False


SEVERITY_VALUES = tuple(item.value for item in Severity)
STATUS_VALUES = tuple(item.value for item in FindingStatus)

__all__ = [
    "EXCLUDED_EVIDENCE_TYPES",
    "REPORT_HTML_ARTIFACT",
    "REPORT_INPUT_LIMIT",
    "REPORT_JSON_ARTIFACT",
    "REPORT_RESULT_ARTIFACT",
    "REPORT_SCHEMA",
    "REPORT_SCHEMA_VERSION",
    "AuditReport",
    "ExecutiveSummary",
    "ReportAsset",
    "ReportAuditMetadata",
    "ReportDhcpSummary",
    "ReportEnvironment",
    "ReportEnvironmentInterface",
    "ReportEvidenceReference",
    "ReportFinding",
    "ReportMetadata",
    "ReportNamingSummary",
    "ReportNeighbor",
    "ReportPassive",
    "ReportRecommendation",
    "ReportRecord",
    "ReportScope",
    "ReportService",
    "ReportSource",
    "ReportStpSummary",
    "SEVERITY_VALUES",
    "STATUS_VALUES",
]
