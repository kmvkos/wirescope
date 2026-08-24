"""Durable report-generation job handler.

This job assembles HTML and JSON reports from stored audit data. It does
not invoke scanners, parse stdout, or write outside the evidence root.
"""

from collections.abc import Callable
import uuid

from config.logging import get_logger
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.errors import JobCancelled
from jobs.models import JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from persistence.models import utc_now
from reports.builder import build_audit_report
from reports.html import render_html
from reports.models import (
    REPORT_HTML_ARTIFACT,
    REPORT_JSON_ARTIFACT,
    REPORT_RESULT_ARTIFACT,
    REPORT_SCHEMA,
    REPORT_SCHEMA_VERSION,
)
from reports.sources import load_report_source
from reports.store import ReportStore
from reports.validate import validate_report_document


class ReportGenerationHandler:
    def __init__(
        self,
        *,
        inventory_factory: (
            Callable[[HandlerContext], InventoryService] | None
        ) = None,
        finding_store_factory: (
            Callable[[HandlerContext], FindingStore] | None
        ) = None,
        report_store_factory: (
            Callable[[HandlerContext], ReportStore] | None
        ) = None,
    ) -> None:
        self.inventory_factory = inventory_factory or (
            lambda context: InventoryService(
                context.evidence_store.database,
                context.settings,
                context.evidence_store,
            )
        )
        self.finding_store_factory = finding_store_factory or (
            lambda context: FindingStore(context.evidence_store.database)
        )
        self.report_store_factory = report_store_factory or (
            lambda context: ReportStore(context.evidence_store.database)
        )
        self.logger = get_logger("reports")

    def execute(self, context: HandlerContext) -> HandlerResult:
        self._ensure_not_cancelled(context)
        self._progress(context, 8, "loading_inputs", "Loading persisted audit data")
        inventory = self.inventory_factory(context)
        findings = self.finding_store_factory(context)
        store = self.report_store_factory(context)
        source = load_report_source(
            audit=context.audit,
            database=context.evidence_store.database,
            inventory=inventory,
            findings=findings,
            evidence_store=context.evidence_store,
        )
        self._ensure_not_cancelled(context)
        self._progress(context, 40, "building_report", "Building versioned report")
        report_id = str(uuid.uuid4())
        generated_at = utc_now()
        actor = context.job.parameters.get("actor")
        if actor is not None:
            actor = str(actor)
        report = build_audit_report(
            source,
            report_id=report_id,
            generated_at=generated_at,
            product=context.settings.app_name,
            version=context.settings.app_version,
            job_id=context.job.id,
            actor=actor,
        )
        document = report.to_document()
        validate_report_document(document)
        html = render_html(report)
        self._ensure_not_cancelled(context)
        self._progress(context, 75, "persisting_report", "Persisting report artifacts")
        json_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type=REPORT_JSON_ARTIFACT,
            document=document,
            retention_class=RetentionClass.REPORT,
            schema_name=REPORT_SCHEMA,
            schema_version=REPORT_SCHEMA_VERSION,
        )
        html_artifact = context.evidence_store.put_bytes(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type=REPORT_HTML_ARTIFACT,
            payload=html.encode("utf-8"),
            content_type="text/html; charset=utf-8",
            extension=".html",
            retention_class=RetentionClass.REPORT,
            schema_name="audit-report-html",
            schema_version=REPORT_SCHEMA_VERSION,
        )
        persisted = store.create(
            audit_id=context.audit.id,
            job_id=context.job.id,
            actor=actor,
            source_hash=report.source_hash,
            summary={
                "schema": "report-summary",
                "schema_version": 1,
                "headline": report.executive_summary.headline,
                "asset_count": report.executive_summary.asset_count,
                "service_count": report.executive_summary.service_count,
                "finding_count": report.executive_summary.finding_count,
                "open_finding_count": report.executive_summary.open_finding_count,
                "by_severity": report.executive_summary.by_severity,
                "json_artifact_id": json_artifact.id,
                "html_artifact_id": html_artifact.id,
            },
            json_artifact_id=json_artifact.id,
            html_artifact_id=html_artifact.id,
            report_id=report.report_id,
            generated_at=generated_at,
        )
        result_document = {
            "schema": "report-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "report_id": persisted.id,
            "json_artifact_id": json_artifact.id,
            "html_artifact_id": html_artifact.id,
            "source_hash": persisted.source_hash,
            "summary": persisted.summary,
        }
        result_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type=REPORT_RESULT_ARTIFACT,
            document=result_document,
            retention_class=RetentionClass.AUDIT,
            schema_name="report-result",
            schema_version=1,
        )
        self.logger.info(
            "report generation completed",
            extra={
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "component": "reports",
                "report_id": persisted.id,
            },
        )
        return HandlerResult(
            result_reference=result_artifact.id,
            summary={
                **persisted.summary,
                "report_id": persisted.id,
                "result_reference": result_artifact.id,
            },
        )

    @staticmethod
    def _progress(
        context: HandlerContext,
        percentage: int,
        stage: str,
        message: str,
    ) -> None:
        context.report_progress(
            JobProgress(
                percentage=percentage,
                stage=stage,
                message=message,
            )
        )

    @staticmethod
    def _ensure_not_cancelled(context: HandlerContext) -> None:
        if context.cancellation_token.cancelled:
            raise JobCancelled("Report generation was cancelled")
