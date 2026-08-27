"""Durable offline Global Correlation Analysis job handler."""

from __future__ import annotations

from types import SimpleNamespace

from findings.store import FindingStore
from global_analysis import GlobalAnalysisSourceError, build_global_analysis
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from jobs.service import JobService


class GlobalAnalysisHandler:
    def execute(self, context: HandlerContext) -> HandlerResult:
        self._ensure_not_cancelled(context)
        traffic_job_id = str(
            context.job.parameters.get("traffic_analysis_job_id") or ""
        ).strip()
        if not traffic_job_id:
            raise JobExecutionError(
                JobError(
                    code="global_analysis_input_missing",
                    category=ErrorCategory.INVALID_INPUT,
                    message="traffic_analysis_job_id is required",
                    component="global_analysis",
                    retryable=False,
                )
            )

        self._progress(context, 10, "loading_inputs", "Loading persisted analysis sources")
        database = context.evidence_store.database
        services = SimpleNamespace(
            settings=context.settings,
            database=database,
            jobs=JobService(database),
            evidence=context.evidence_store,
            inventory=InventoryService(
                database,
                context.settings,
                context.evidence_store,
            ),
            findings=FindingStore(database),
        )
        self._ensure_not_cancelled(context)
        self._progress(context, 35, "correlating", "Correlating inventory, traffic, findings, and topology")
        try:
            document = build_global_analysis(
                services,
                context.audit.id,
                traffic_analysis_job_id=traffic_job_id,
            )
        except GlobalAnalysisSourceError as exc:
            raise JobExecutionError(
                JobError(
                    code="global_analysis_source_invalid",
                    category=ErrorCategory.INVALID_INPUT,
                    message=str(exc),
                    component="global_analysis",
                    retryable=False,
                )
            ) from exc

        self._ensure_not_cancelled(context)
        self._progress(context, 80, "persisting", "Persisting canonical global analysis")
        artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="global_analysis_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="global-analysis",
            schema_version=1,
        )
        self._progress(context, 100, "completed", "Global correlation analysis completed")
        summary = dict(document.get("summary") or {})
        summary.update(
            {
                "schema": "global-analysis-summary",
                "schema_version": 1,
                "result_reference": artifact.id,
                "traffic_analysis_job_id": traffic_job_id,
                "partial": bool(document.get("partial")),
            }
        )
        return HandlerResult(
            result_reference=artifact.id,
            summary=summary,
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
            raise JobCancelled("Global correlation analysis was cancelled")
