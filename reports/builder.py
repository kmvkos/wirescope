"""Assemble a versioned audit report from persisted, already-normalized data."""

from datetime import datetime
import hashlib
import json
from typing import Any

from findings.models import FindingStatus, SEVERITY_RANK, Severity
from engine.segment import tagged_vlan_headline
from reports.models import (
    REPORT_INPUT_LIMIT,
    REPORT_SCHEMA,
    REPORT_SCHEMA_VERSION,
    AuditReport,
    ExecutiveSummary,
    ReportAsset,
    ReportAuditMetadata,
    ReportEnvironment,
    ReportEnvironmentInterface,
    ReportFinding,
    ReportMetadata,
    ReportRecommendation,
    ReportScope,
    ReportSource,
    SEVERITY_VALUES,
    STATUS_VALUES,
)
from reports.passive import project_passive


def build_audit_report(
    source: ReportSource,
    *,
    report_id: str,
    generated_at: datetime,
    product: str,
    version: str,
    job_id: str | None = None,
    actor: str | None = None,
) -> AuditReport:
    findings = list(source.findings)
    open_findings = [
        item for item in findings if item.status == FindingStatus.OPEN.value
    ]
    by_severity = {name: 0 for name in SEVERITY_VALUES}
    by_status = {name: 0 for name in STATUS_VALUES}
    for item in findings:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        by_status[item.status] = by_status.get(item.status, 0) + 1
    highest = _highest_severity(open_findings)
    confirmed = bool(source.confirmed_scope)
    passive = project_passive(
        environment=source.environment,
        audit_interface=source.audit_interface,
        audit_summary=source.audit_summary,
        passive_result=source.passive_result,
    )
    report = AuditReport(
        schema=REPORT_SCHEMA,
        schema_version=REPORT_SCHEMA_VERSION,
        report_id=report_id,
        generated_at=generated_at,
        source_hash="",
        audit=ReportAuditMetadata(
            id=source.audit_id,
            status=source.audit_status,
            profile=source.audit_profile,
            interface=source.audit_interface,
            actor=source.audit_actor,
            created_at=source.audit_created_at,
            started_at=source.audit_started_at,
            finished_at=source.audit_finished_at,
            summary=dict(source.audit_summary),
        ),
        executive_summary=ExecutiveSummary(
            headline=_headline(
                open_findings,
                highest,
                confirmed,
                frame_count=passive.frame_count,
                asset_count=len(source.assets),
                detected_sensors=source.detected_sensors or passive.detected_sensors,
                tagged_vlan_ids=passive.tagged_vlan_ids,
                untagged_traffic_observed=passive.untagged_traffic_observed,
            ),
            asset_count=len(source.assets),
            service_count=len(source.services),
            finding_count=len(findings),
            open_finding_count=len(open_findings),
            by_severity=by_severity,
            by_status=by_status,
            highest_open_severity=highest,
            confirmed_scope=confirmed,
            detected_sensors=list(
                source.detected_sensors or passive.detected_sensors
            ),
            frame_count=passive.frame_count,
            had_l3_address=passive.had_l3_address,
            tagged_vlan_ids=list(passive.tagged_vlan_ids),
            segment_status=passive.segment_status,
            segment_note=passive.segment_note,
        ),
        environment=_environment(
            source.environment,
            capture_interface=passive.capture_interface,
            had_l3_address=passive.had_l3_address,
        ),
        passive=passive,
        scope=_scope(source),
        assets=list(source.assets),
        services=list(source.services),
        findings=findings,
        recommendations=_recommendations(open_findings),
        evidence_references=list(source.evidence_references),
        metadata=ReportMetadata(
            product=product,
            version=version,
            job_id=job_id,
            actor=actor,
            raw_provider_output_excluded=True,
            truncated=source.truncated,
            input_limits={
                "assets": REPORT_INPUT_LIMIT,
                "services": REPORT_INPUT_LIMIT,
                "findings": REPORT_INPUT_LIMIT,
                "evidence_references": REPORT_INPUT_LIMIT,
            },
            warnings=list(source.warnings),
        ),
    )
    return report.model_copy(update={"source_hash": source_hash_for(report)})


def source_hash_for(report: AuditReport) -> str:
    payload = report.to_document()
    payload["report_id"] = ""
    payload["generated_at"] = ""
    payload["source_hash"] = ""
    audit = dict(payload.get("audit") or {})
    audit["status"] = ""
    audit["started_at"] = None
    audit["finished_at"] = None
    audit["summary"] = {}
    payload["audit"] = audit
    metadata = dict(payload.get("metadata") or {})
    metadata["job_id"] = ""
    payload["metadata"] = metadata
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _environment(
    raw: dict[str, Any] | None,
    *,
    capture_interface: str | None = None,
    had_l3_address: bool | None = None,
) -> ReportEnvironment:
    if not raw:
        return ReportEnvironment(
            capture_interface=capture_interface,
            had_l3_address=had_l3_address,
        )
    interfaces: list[ReportEnvironmentInterface] = []
    for item in raw.get("interfaces") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        interfaces.append(
            ReportEnvironmentInterface(
                name=name,
                state=_optional_str(item.get("state")),
                mac=_optional_str(item.get("mac")),
                ipv4=_string_list(item.get("ipv4")),
                ipv6=_string_list(item.get("ipv6")),
            )
        )
    default_route = raw.get("default_route")
    route: dict[str, str | None] | None = None
    if isinstance(default_route, dict):
        route = {
            "gateway": _optional_str(default_route.get("gateway")),
            "interface": _optional_str(default_route.get("interface")),
        }
    return ReportEnvironment(
        hostname=_optional_str(raw.get("hostname")),
        capture_interface=capture_interface,
        had_l3_address=had_l3_address,
        interfaces=interfaces,
        default_route=route,
        dns=_string_list(raw.get("dns")),
    )


def _scope(source: ReportSource) -> ReportScope:
    confirmed = source.confirmed_scope or {}
    if not confirmed:
        return ReportScope(
            confirmed=False,
            audit_scope=dict(source.audit_scope),
            interface=source.audit_interface,
            profile=source.audit_profile,
        )
    families = [
        int(item)
        for item in confirmed.get("address_families") or []
        if str(item).lstrip("-").isdigit()
    ]
    address_count = confirmed.get("address_count")
    return ReportScope(
        confirmed=True,
        audit_scope=dict(source.audit_scope),
        profile=_optional_str(confirmed.get("profile")) or source.audit_profile,
        interface=(
            _optional_str(confirmed.get("interface")) or source.audit_interface
        ),
        targets=_string_list(confirmed.get("targets")),
        address_count=int(address_count) if address_count is not None else None,
        address_families=families,
        timing_policy=_optional_str(confirmed.get("timing_policy")),
        snapshot_hash=_optional_str(confirmed.get("snapshot_hash")),
    )


def _recommendations(
    open_findings: list[ReportFinding],
) -> list[ReportRecommendation]:
    grouped: dict[tuple[str, str], ReportRecommendation] = {}
    order: list[tuple[str, str]] = []
    for item in open_findings:
        key = (item.rule_id, item.recommendation)
        current = grouped.get(key)
        if current is None:
            grouped[key] = ReportRecommendation(
                rule_id=item.rule_id,
                title=item.title,
                severity=item.severity,
                recommendation=item.recommendation,
                finding_ids=[item.id],
                affected_asset_ids=(
                    [item.asset_id] if item.asset_id else []
                ),
            )
            order.append(key)
            continue
        finding_ids = list(current.finding_ids)
        if item.id not in finding_ids:
            finding_ids.append(item.id)
        assets = list(current.affected_asset_ids)
        if item.asset_id and item.asset_id not in assets:
            assets.append(item.asset_id)
        grouped[key] = current.model_copy(
            update={
                "finding_ids": finding_ids,
                "affected_asset_ids": assets,
                "severity": _worse_severity(current.severity, item.severity),
            }
        )
    return [grouped[key] for key in order]


def _headline(
    open_findings: list[ReportFinding],
    highest: str | None,
    confirmed: bool,
    *,
    frame_count: int | None = None,
    asset_count: int = 0,
    detected_sensors: list[str] | None = None,
    tagged_vlan_ids: list[int] | None = None,
    untagged_traffic_observed: bool = False,
) -> str:
    if highest == Severity.CRITICAL.value:
        return "Open critical findings require attention"
    if highest == Severity.HIGH.value:
        return "Open high-severity findings were identified"
    if highest == Severity.MEDIUM.value:
        return "Open medium-severity findings were identified"
    if open_findings:
        return "Open findings were recorded"
    if frame_count == 0 and asset_count == 0:
        return "Capture completed with no frames"
    if tagged_vlan_ids:
        return tagged_vlan_headline(tagged_vlan_ids)
    if untagged_traffic_observed and asset_count == 0:
        return "Untagged traffic was observed; VLAN ID is unknown"
    if confirmed:
        return "No open findings were recorded for the confirmed scope"
    if asset_count == 0 and detected_sensors:
        return "Passive observations were recorded"
    if asset_count == 0:
        return "No hosts, services, or findings were recorded"
    return "No open findings were recorded"


def _highest_severity(findings: list[ReportFinding]) -> str | None:
    if not findings:
        return None
    ranked = sorted(
        findings,
        key=lambda item: SEVERITY_RANK.get(
            Severity(item.severity),
            99,
        ),
    )
    return ranked[0].severity


def _worse_severity(left: str, right: str) -> str:
    left_rank = SEVERITY_RANK.get(Severity(left), 99)
    right_rank = SEVERITY_RANK.get(Severity(right), 99)
    return left if left_rank <= right_rank else right


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for entry in value:
        text = str(entry).strip()
        if text:
            items.append(text)
    return items
