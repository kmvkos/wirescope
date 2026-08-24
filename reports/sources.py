"""Load persisted audit data for report generation.

Reports never invoke scanners, read tool stdout, or follow caller-supplied
filesystem paths.
"""

from typing import Any

from sqlalchemy import select

from findings.models import SEVERITY_RANK, Severity
from findings.store import FindingStore
from inventory.models import AssetRecord, ServiceRecord
from inventory.service import InventoryService
from jobs.errors import JobExecutionError
from jobs.models import ArtifactRecord, RetentionClass
from persistence.database import Database
from persistence.models import ArtifactModel
from reports.models import (
    EXCLUDED_EVIDENCE_TYPES,
    REPORT_INPUT_LIMIT,
    ReportAsset,
    ReportEvidenceReference,
    ReportFinding,
    ReportService,
    ReportSource,
)
from storage.evidence import EvidenceStore


def load_report_source(
    *,
    audit,
    database: Database,
    inventory: InventoryService,
    findings: FindingStore,
    evidence_store: EvidenceStore,
) -> ReportSource:
    warnings: list[str] = []
    truncated = False
    assets_page = inventory.list_assets(
        audit_id=audit.id,
        limit=REPORT_INPUT_LIMIT,
        offset=0,
        include_services=False,
    )
    services_page = inventory.list_services(
        audit_id=audit.id,
        limit=REPORT_INPUT_LIMIT,
        offset=0,
    )
    findings_page = findings.list_findings(
        audit_id=audit.id,
        limit=REPORT_INPUT_LIMIT,
        offset=0,
    )
    if assets_page.total > len(assets_page.items):
        truncated = True
        warnings.append("Asset list exceeded the report input limit")
    if services_page.total > len(services_page.items):
        truncated = True
        warnings.append("Service list exceeded the report input limit")
    if findings_page.total > len(findings_page.items):
        truncated = True
        warnings.append("Finding list exceeded the report input limit")

    artifacts = _list_artifacts(database, audit.id)
    evidence = [
        _evidence_reference(item)
        for item in artifacts
        if item.artifact_type not in EXCLUDED_EVIDENCE_TYPES
    ]
    if len(evidence) > REPORT_INPUT_LIMIT:
        evidence = evidence[:REPORT_INPUT_LIMIT]
        truncated = True
        warnings.append("Evidence reference list exceeded the report input limit")

    environment, env_warning = _load_environment(
        audit.environment_snapshot_reference,
        database,
        evidence_store,
    )
    if env_warning:
        warnings.append(env_warning)

    confirmed = inventory.latest_scope(audit.id)
    confirmed_payload = None
    if confirmed is not None:
        confirmed_payload = {
            "id": confirmed.id,
            "profile": confirmed.profile.value,
            "interface": confirmed.interface,
            "targets": list(confirmed.targets),
            "address_families": list(confirmed.address_families),
            "address_count": confirmed.address_count,
            "timing_policy": confirmed.timing_policy,
            "snapshot_hash": confirmed.snapshot_hash,
        }

    detected_sensors, passive_result, sensor_warning = _load_passive(
        artifacts,
        evidence_store,
    )
    if sensor_warning:
        warnings.append(sensor_warning)

    report_assets = sorted(
        (_report_asset(item) for item in assets_page.items),
        key=lambda item: item.id,
    )
    report_services = sorted(
        (_report_service(item) for item in services_page.items),
        key=lambda item: (item.protocol, item.port, item.id),
    )
    report_findings = sorted(
        (_report_finding(item) for item in findings_page.items),
        key=lambda item: (
            SEVERITY_RANK.get(Severity(item.severity), 99),
            item.rule_id,
            item.id,
        ),
    )
    return ReportSource(
        audit_id=audit.id,
        audit_status=audit.status.value,
        audit_profile=audit.profile,
        audit_interface=audit.interface,
        audit_actor=audit.actor,
        audit_created_at=audit.created_at,
        audit_started_at=audit.started_at,
        audit_finished_at=audit.finished_at,
        audit_summary=dict(audit.summary or {}),
        audit_scope=dict(audit.scope or {}),
        environment=environment,
        confirmed_scope=confirmed_payload,
        assets=report_assets,
        services=report_services,
        findings=report_findings,
        evidence_references=evidence,
        detected_sensors=detected_sensors,
        passive_result=passive_result,
        warnings=warnings,
        truncated=truncated,
    )


def _report_asset(asset: AssetRecord) -> ReportAsset:
    return ReportAsset(
        id=asset.id,
        state=asset.state.value,
        mac=asset.mac,
        vendor=asset.vendor,
        device_class_hint=asset.device_class_hint.value,
        os_name=asset.os_name,
        addresses=sorted(item.address for item in asset.addresses),
        names=sorted(item.name for item in asset.names),
    )


def _report_service(service: ServiceRecord) -> ReportService:
    return ReportService(
        id=service.id,
        asset_id=service.asset_id,
        protocol=service.protocol,
        port=service.port,
        state=service.state,
        service_name=service.service_name,
        product=service.product,
        version=service.version,
        tunnel=service.tunnel,
    )


def _report_finding(finding) -> ReportFinding:
    return ReportFinding(
        id=finding.id,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        family=finding.family,
        title=finding.title,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        status=finding.status.value,
        asset_id=finding.asset_id,
        service_id=finding.service_id,
        description=finding.description,
        rationale=finding.rationale,
        recommendation=finding.recommendation,
        observation_ids=list(finding.observation_ids),
        evidence_artifact_ids=list(finding.evidence_artifact_ids),
        data=dict(finding.data or {}),
    )


def _list_artifacts(database: Database, audit_id: str) -> list[ArtifactRecord]:
    with database.session() as session:
        rows = session.scalars(
            select(ArtifactModel)
            .where(ArtifactModel.audit_id == audit_id)
            .order_by(ArtifactModel.created_at, ArtifactModel.id)
        ).all()
        return [_artifact_record(row) for row in rows]


def _artifact_record(model: ArtifactModel) -> ArtifactRecord:
    return ArtifactRecord(
        id=model.id,
        audit_id=model.audit_id,
        job_id=model.job_id,
        artifact_type=model.artifact_type,
        relative_path=model.relative_path,
        content_type=model.content_type,
        size=model.size,
        sha256=model.sha256,
        created_at=model.created_at,
        retention_class=RetentionClass(model.retention_class),
        schema_name=model.schema_name,
        schema_version=model.schema_version,
    )


def _evidence_reference(artifact: ArtifactRecord) -> ReportEvidenceReference:
    return ReportEvidenceReference(
        id=artifact.id,
        artifact_type=artifact.artifact_type,
        content_type=artifact.content_type,
        size=artifact.size,
        sha256=artifact.sha256,
        schema_name=artifact.schema_name,
        schema_version=artifact.schema_version,
        created_at=artifact.created_at,
    )


def _load_environment(
    reference: str | None,
    database: Database,
    evidence_store: EvidenceStore,
) -> tuple[dict[str, Any] | None, str | None]:
    if not reference:
        return None, None
    artifact = _artifact_by_id(database, reference)
    if artifact is None:
        return None, "Environment snapshot artifact was not found"
    try:
        document = evidence_store.read_json(artifact)
    except JobExecutionError:
        return None, "Environment snapshot could not be read"
    environment = document.get("environment")
    if not isinstance(environment, dict):
        return None, "Environment snapshot did not contain an object"
    return environment, None


def _load_passive(
    artifacts: list[ArtifactRecord],
    evidence_store: EvidenceStore,
) -> tuple[list[str], dict[str, Any] | None, str | None]:
    latest = None
    for artifact in reversed(artifacts):
        if artifact.artifact_type == "passive_result":
            latest = artifact
            break
    if latest is None:
        return [], None, None
    try:
        document = evidence_store.read_json(latest)
    except JobExecutionError:
        return [], None, "Passive result artifact could not be read"
    sensors = (
        (document.get("result") or {}).get("sensors")
        if isinstance(document.get("result"), dict)
        else None
    )
    if not isinstance(sensors, dict):
        return [], document if isinstance(document, dict) else None, None
    detected = sorted(
        str(name)
        for name, payload in sensors.items()
        if isinstance(payload, dict)
        and (
            payload.get("detected") is True
            or payload.get("status") == "detected"
        )
    )
    return detected, document, None


def _artifact_by_id(
    database: Database,
    artifact_id: str,
) -> ArtifactRecord | None:
    with database.session() as session:
        model = session.get(ArtifactModel, artifact_id)
        if model is None:
            return None
        return _artifact_record(model)
