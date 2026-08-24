"""Durable findings-evaluation job handler.

This job interprets stored protocol observations, inventory services, and
passive assessment artifacts. It does not invoke scanners or parse stdout.
"""

from collections.abc import Callable

from config.logging import get_logger
from findings.engine import evaluate_findings
from findings.registry import RuleRegistry, default_registry
from findings.sources import load_evaluation_context
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.errors import JobCancelled
from jobs.models import JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from protocol_audits.store import ProtocolObservationStore


class FindingsEvaluationHandler:
    def __init__(
        self,
        *,
        registry: RuleRegistry | None = None,
        inventory_factory: (
            Callable[[HandlerContext], InventoryService] | None
        ) = None,
        observation_store_factory: (
            Callable[[HandlerContext], ProtocolObservationStore] | None
        ) = None,
        finding_store_factory: (
            Callable[[HandlerContext], FindingStore] | None
        ) = None,
    ) -> None:
        self.registry = registry or default_registry()
        self.inventory_factory = inventory_factory or (
            lambda context: InventoryService(
                context.evidence_store.database,
                context.settings,
                context.evidence_store,
            )
        )
        self.observation_store_factory = observation_store_factory or (
            lambda context: ProtocolObservationStore(
                context.evidence_store.database
            )
        )
        self.finding_store_factory = finding_store_factory or (
            lambda context: FindingStore(context.evidence_store.database)
        )
        self.logger = get_logger("findings")

    def execute(self, context: HandlerContext) -> HandlerResult:
        self._ensure_not_cancelled(context)
        self._progress(context, 8, "loading_inputs", "Loading stored observations")
        inventory = self.inventory_factory(context)
        observations = self.observation_store_factory(context)
        store = self.finding_store_factory(context)
        evaluation = load_evaluation_context(
            audit_id=context.audit.id,
            database=context.evidence_store.database,
            inventory=inventory,
            observations=observations,
            evidence_store=context.evidence_store,
        )
        self._ensure_not_cancelled(context)
        self._progress(context, 40, "evaluating_rules", "Evaluating finding rules")
        drafts = evaluate_findings(evaluation, self.registry)
        self._ensure_not_cancelled(context)
        self._progress(context, 75, "persisting_findings", "Persisting findings")
        persisted = store.upsert_evaluation(
            audit_id=context.audit.id,
            drafts=drafts,
        )
        counts = store.counts_by_severity(context.audit.id)
        summary = {
            "schema": "findings-summary",
            "schema_version": 1,
            "rules": list(self.registry.rule_ids),
            "observation_count": len(evaluation.observations),
            "service_count": len(evaluation.services),
            "draft_count": len(drafts),
            "findings": len(persisted),
            "by_severity": counts,
            "passive_artifact_id": evaluation.passive_artifact_id,
        }
        document = {
            "schema": "findings-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "summary": summary,
            "finding_ids": [item.id for item in persisted],
        }
        artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="findings_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="findings-result",
            schema_version=1,
        )
        self.logger.info(
            "findings evaluation completed",
            extra={
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "component": "findings",
                "findings": len(persisted),
            },
        )
        return HandlerResult(
            result_reference=artifact.id,
            summary={
                **summary,
                "result_reference": artifact.id,
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
            raise JobCancelled("Findings evaluation was cancelled")
