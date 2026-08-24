"""Minimal durable schema for audits, jobs, events, and artifacts."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AuditModel(Base):
    __tablename__ = "audits"
    __table_args__ = (
        CheckConstraint(
            "status IN ('created','running','completed','failed',"
            "'cancelled','interrupted')",
            name="ck_audits_status",
        ),
        Index("ix_audits_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    interface: Mapped[str | None] = mapped_column(String(64))
    scope_json: Mapped[dict[str, Any]] = mapped_column(
        "scope",
        JSON,
        default=dict,
        nullable=False,
    )
    actor: Mapped[str | None] = mapped_column(String(128))
    environment_snapshot_reference: Mapped[str | None] = mapped_column(
        String(36)
    )
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    error: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    jobs: Mapped[list["JobModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )
    artifacts: Mapped[list["ArtifactModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )
    confirmed_scopes: Mapped[list["ConfirmedScopeModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )
    assets: Mapped[list["AssetModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )
    protocol_observations: Mapped[list["ProtocolObservationModel"]] = (
        relationship(
            back_populates="audit",
            cascade="all, delete-orphan",
        )
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )
    reports: Mapped[list["ReportModel"]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
    )


class JobModel(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','completed','failed',"
            "'cancelled','interrupted')",
            name="ck_jobs_status",
        ),
        CheckConstraint(
            "progress >= 0 AND progress <= 100",
            name="ck_jobs_progress",
        ),
        Index(
            "ix_jobs_queue_claim",
            "status",
            "priority",
            "created_at",
        ),
        Index("ix_jobs_audit_created", "audit_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stage: Mapped[str] = mapped_column(
        String(64),
        default="queued",
        nullable=False,
    )
    message: Mapped[str | None] = mapped_column(String(512))
    target: Mapped[str | None] = mapped_column(String(512))
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    result_reference: Mapped[str | None] = mapped_column(String(36))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_category: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(Text)
    error_component: Mapped[str | None] = mapped_column(String(128))
    error_retryable: Mapped[bool | None] = mapped_column(Boolean)
    error_details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    worker_id: Mapped[str | None] = mapped_column(String(128))
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resource_key: Mapped[str | None] = mapped_column(String(256))
    resource_group: Mapped[str | None] = mapped_column(String(64))
    resource_limit: Mapped[int | None] = mapped_column(Integer)

    audit: Mapped[AuditModel] = relationship(back_populates="jobs")
    events: Mapped[list["JobEventModel"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
    )
    artifacts: Mapped[list["ArtifactModel"]] = relationship(
        back_populates="job",
    )


class JobEventModel(Base):
    __tablename__ = "job_events"
    __table_args__ = (
        Index("ix_job_events_job_created", "job_id", "created_at"),
        Index("ix_job_events_audit_created", "audit_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    stage: Mapped[str | None] = mapped_column(String(64))
    progress: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    job: Mapped[JobModel] = relationship(back_populates="events")


class ArtifactModel(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint(
            "retention_class IN ('temporary','audit','debug','report')",
            name="ck_artifacts_retention_class",
        ),
        UniqueConstraint("relative_path", name="uq_artifacts_relative_path"),
        Index("ix_artifacts_audit_created", "audit_id", "created_at"),
        Index("ix_artifacts_job_created", "job_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL")
    )
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    retention_class: Mapped[str] = mapped_column(String(20), nullable=False)
    schema_name: Mapped[str | None] = mapped_column(String(64))
    schema_version: Mapped[int | None] = mapped_column(Integer)

    audit: Mapped[AuditModel] = relationship(back_populates="artifacts")
    job: Mapped[JobModel | None] = relationship(back_populates="artifacts")


class ResourceLockModel(Base):
    __tablename__ = "resource_locks"
    __table_args__ = (
        UniqueConstraint("job_id", name="uq_resource_locks_job_id"),
        Index("ix_resource_locks_group", "resource_group"),
    )

    resource_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    resource_group: Mapped[str | None] = mapped_column(String(64))
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class WorkerModel(Base):
    __tablename__ = "workers"
    __table_args__ = (
        CheckConstraint(
            "status IN ('starting','idle','running','stopped')",
            name="ck_workers_status",
        ),
        Index("ix_workers_heartbeat", "heartbeat_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    current_job_id: Mapped[str | None] = mapped_column(String(36))


class ConfirmedScopeModel(Base):
    __tablename__ = "confirmed_scopes"
    __table_args__ = (
        UniqueConstraint(
            "audit_id",
            "snapshot_hash",
            name="uq_confirmed_scopes_audit_hash",
        ),
        Index("ix_confirmed_scopes_audit_created", "audit_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    profile: Mapped[str] = mapped_column(String(20), nullable=False)
    interface: Mapped[str] = mapped_column(String(64), nullable=False)
    targets: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    address_families: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    address_count: Mapped[int] = mapped_column(Integer, nullable=False)
    route_context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    timing_policy: Mapped[str] = mapped_column(String(8), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(128))
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    audit: Mapped[AuditModel] = relationship(
        back_populates="confirmed_scopes"
    )


class AssetModel(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "state IN ('observed','responsive','unresponsive','unknown')",
            name="ck_assets_state",
        ),
        UniqueConstraint("audit_id", "mac", name="uq_assets_audit_mac"),
        Index("ix_assets_audit_state", "audit_id", "state"),
        Index("ix_assets_audit_vendor", "audit_id", "vendor"),
        Index(
            "ix_assets_audit_device_class",
            "audit_id",
            "device_class_hint",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    mac: Mapped[str | None] = mapped_column(String(17))
    vendor: Mapped[str | None] = mapped_column(String(256))
    vendor_source: Mapped[str | None] = mapped_column(String(128))
    vendor_database_version: Mapped[str | None] = mapped_column(String(64))
    device_class_hint: Mapped[str] = mapped_column(
        String(32),
        default="unknown",
        nullable=False,
    )
    device_class_confidence: Mapped[str] = mapped_column(
        String(16),
        default="unknown",
        nullable=False,
    )
    os_family: Mapped[str | None] = mapped_column(String(128))
    os_name: Mapped[str | None] = mapped_column(String(512))
    os_generation: Mapped[str | None] = mapped_column(String(64))
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON,
        default=dict,
        nullable=False,
    )

    audit: Mapped[AuditModel] = relationship(back_populates="assets")
    addresses: Mapped[list["AssetAddressModel"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    names: Mapped[list["AssetNameModel"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    services: Mapped[list["ServiceModel"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    observations: Mapped[list["AssetObservationModel"]] = relationship(
        back_populates="asset",
    )
    protocol_observations: Mapped[list["ProtocolObservationModel"]] = (
        relationship(
            back_populates="asset",
        )
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="asset",
    )


class AssetAddressModel(Base):
    __tablename__ = "asset_addresses"
    __table_args__ = (
        UniqueConstraint(
            "audit_id",
            "address",
            name="uq_asset_addresses_audit_address",
        ),
        Index("ix_asset_addresses_asset", "asset_id"),
        Index("ix_asset_addresses_audit_family", "audit_id", "family"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    address: Mapped[str] = mapped_column(String(45), nullable=False)
    family: Mapped[int] = mapped_column(Integer, nullable=False)
    is_primary: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)

    asset: Mapped[AssetModel] = relationship(back_populates="addresses")


class AssetNameModel(Base):
    __tablename__ = "asset_names"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "name",
            "name_type",
            "source",
            name="uq_asset_names_provenance",
        ),
        Index("ix_asset_names_audit_name", "audit_id", "name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    name_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    asset: Mapped[AssetModel] = relationship(back_populates="names")


class ServiceModel(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "protocol",
            "port",
            name="uq_services_asset_protocol_port",
        ),
        Index("ix_services_audit_protocol_port", "audit_id", "protocol", "port"),
        Index("ix_services_audit_name", "audit_id", "service_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(128))
    service_name: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128))
    extra_info: Mapped[str | None] = mapped_column(String(512))
    tunnel: Mapped[str | None] = mapped_column(String(32))
    cpe: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    banner: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    asset: Mapped[AssetModel] = relationship(back_populates="services")
    protocol_observations: Mapped[list["ProtocolObservationModel"]] = (
        relationship(
            back_populates="service",
        )
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="service",
    )


class AssetObservationModel(Base):
    __tablename__ = "asset_observations"
    __table_args__ = (
        Index("ix_asset_observations_audit_created", "audit_id", "created_at"),
        Index("ix_asset_observations_asset_created", "asset_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL")
    )
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_reference: Mapped[str | None] = mapped_column(String(128))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    asset: Mapped[AssetModel | None] = relationship(
        back_populates="observations"
    )


class ProtocolObservationModel(Base):
    __tablename__ = "protocol_observations"
    __table_args__ = (
        CheckConstraint(
            "confidence IN ('confirmed','high','medium','low',"
            "'hint','unknown')",
            name="ck_protocol_observations_confidence",
        ),
        UniqueConstraint(
            "audit_id",
            "asset_id",
            "service_id",
            "module",
            "kind",
            "dedupe_key",
            name="uq_protocol_observations_identity",
        ),
        Index(
            "ix_protocol_observations_audit_module",
            "audit_id",
            "module",
            "protocol",
        ),
        Index(
            "ix_protocol_observations_audit_asset",
            "audit_id",
            "asset_id",
        ),
        Index(
            "ix_protocol_observations_audit_service",
            "audit_id",
            "service_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    service_id: Mapped[str] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
    )
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(
        String(64),
        default="",
        nullable=False,
    )
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_artifact_id: Mapped[str | None] = mapped_column(String(36))
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    audit: Mapped["AuditModel"] = relationship(
        back_populates="protocol_observations"
    )
    asset: Mapped[AssetModel] = relationship(
        back_populates="protocol_observations"
    )
    service: Mapped[ServiceModel] = relationship(
        back_populates="protocol_observations"
    )


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "confidence IN ('confirmed','high','medium','low',"
            "'hint','unknown')",
            name="ck_findings_confidence",
        ),
        CheckConstraint(
            "status IN ('open','suppressed','accepted_risk')",
            name="ck_findings_status",
        ),
        UniqueConstraint(
            "audit_id",
            "rule_id",
            "dedupe_key",
            name="uq_findings_identity",
        ),
        Index("ix_findings_audit_severity", "audit_id", "severity"),
        Index("ix_findings_audit_status", "audit_id", "status"),
        Index("ix_findings_audit_asset", "audit_id", "asset_id"),
        Index("ix_findings_audit_family", "audit_id", "family"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    service_id: Mapped[str | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL")
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    family: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    observation_ids: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    evidence_artifact_ids: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    audit: Mapped["AuditModel"] = relationship(back_populates="findings")
    asset: Mapped[AssetModel | None] = relationship(back_populates="findings")
    service: Mapped[ServiceModel | None] = relationship(
        back_populates="findings"
    )
    state_events: Mapped[list["FindingStateEventModel"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class FindingStateEventModel(Base):
    __tablename__ = "finding_state_events"
    __table_args__ = (
        CheckConstraint(
            "from_status IN ('open','suppressed','accepted_risk')",
            name="ck_finding_state_events_from_status",
        ),
        CheckConstraint(
            "to_status IN ('open','suppressed','accepted_risk')",
            name="ck_finding_state_events_to_status",
        ),
        Index(
            "ix_finding_state_events_finding",
            "finding_id",
            "created_at",
        ),
        Index("ix_finding_state_events_audit", "audit_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    finding: Mapped[FindingModel] = relationship(back_populates="state_events")


class ReportModel(Base):
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_audit_generated", "audit_id", "generated_at"),
        Index("ix_reports_job", "job_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"),
        nullable=False,
    )
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL")
    )
    schema_name: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    actor: Mapped[str | None] = mapped_column(String(128))
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    json_artifact_id: Mapped[str] = mapped_column(String(36), nullable=False)
    html_artifact_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    audit: Mapped["AuditModel"] = relationship(back_populates="reports")


class UserModel(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('auditor','viewer')",
            name="ck_users_role",
        ),
        Index("ix_users_username", "username", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    disabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    sessions: Mapped[list["SessionModel"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class SessionModel(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user", "user_id"),
        Index("ix_sessions_expires", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    user: Mapped["UserModel"] = relationship(back_populates="sessions")
