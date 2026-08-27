"""Persisted-source runtime for Global Correlation Analysis.

The pure assembler remains in ``global_analysis.builder``. This module owns
loading persisted WireScope state and offline topology projection so durable
jobs and read-only API previews share exactly the same contract.
"""

from __future__ import annotations

from typing import Any

from global_analysis.builder import (
    GlobalAnalysisSourceError,
    _traffic_source,
    assemble_global_analysis,
)
from global_analysis.enrich import enrich_global_analysis
from reports.passive import project_passive
from reports.sources import load_report_source
from topology import TopologySourceError, build_topology


def build_global_analysis(
    services,
    audit_id: str,
    *,
    traffic_analysis_job_id: str,
) -> dict[str, Any]:
    audit = services.jobs.get_audit(audit_id)
    report_source = load_report_source(
        audit=audit,
        database=services.database,
        inventory=services.inventory,
        findings=services.findings,
        evidence_store=services.evidence,
    )
    traffic_job, traffic_document = _traffic_source(services, traffic_analysis_job_id)
    try:
        topology = build_topology(
            services,
            audit_id,
            traffic_analysis_job_id=traffic_analysis_job_id,
        )
    except TopologySourceError as exc:
        raise GlobalAnalysisSourceError(str(exc)) from exc

    document = assemble_global_analysis(
        audit={
            "id": audit.id,
            "profile": audit.profile,
            "interface": audit.interface,
            "status": audit.status.value,
        },
        assets=[item.model_dump(mode="json") for item in report_source.assets],
        services=[item.model_dump(mode="json") for item in report_source.services],
        findings=[item.model_dump(mode="json") for item in report_source.findings],
        traffic_job={
            "id": traffic_job.id,
            "audit_id": traffic_job.audit_id,
            "result_reference": traffic_job.result_reference,
        },
        traffic_analysis=traffic_document,
        topology=topology,
        source_warnings=list(report_source.warnings or []),
        source_truncated=bool(report_source.truncated),
    )

    passive = project_passive(
        environment=report_source.environment,
        audit_interface=audit.interface,
        audit_summary=dict(audit.summary or {}),
        passive_result=report_source.passive_result,
    ).model_dump(mode="json")
    evidence_references = [
        item.model_dump(mode="json") for item in report_source.evidence_references
    ]
    if traffic_job.result_reference:
        try:
            traffic_artifact = services.jobs.artifact(traffic_job.result_reference)
        except Exception:
            traffic_artifact = None
        if traffic_artifact is not None and not any(
            str(item.get("id")) == traffic_artifact.id for item in evidence_references
        ):
            evidence_references.append(traffic_artifact.model_dump(mode="json"))

    return enrich_global_analysis(
        document,
        environment=report_source.environment,
        passive=passive,
        topology=topology,
        traffic_analysis=traffic_document,
        evidence_references=evidence_references,
    )
