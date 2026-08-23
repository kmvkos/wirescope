"""Durable protocol-audit job handler."""

from collections.abc import Callable
from typing import Any

from config.logging import get_logger
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from protocol_audits.execute import ProtocolModuleRunner
from protocol_audits.matching import match_work
from protocol_audits.models import ProtocolAuditProfile
from protocol_audits.registry import ModuleRegistry, default_registry
from protocol_audits.store import ProtocolObservationStore
from providers.tools import ToolRunner


class ProtocolAuditHandler:
    def __init__(
        self,
        *,
        registry: ModuleRegistry | None = None,
        runner_factory: Callable[[HandlerContext], ToolRunner] | None = None,
        inventory_factory: (
            Callable[[HandlerContext], InventoryService] | None
        ) = None,
        observation_store_factory: (
            Callable[[HandlerContext], ProtocolObservationStore] | None
        ) = None,
    ) -> None:
        self.registry = registry or default_registry()
        self.runner_factory = runner_factory or (lambda _context: ToolRunner())
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
        self.logger = get_logger("protocol_audit")

    def execute(self, context: HandlerContext) -> HandlerResult:
        self._ensure_not_cancelled(context)
        self._progress(context, 5, "loading_inventory", "Loading inventory")
        inventory = self.inventory_factory(context)
        store = self.observation_store_factory(context)
        runner = self.runner_factory(context)
        profile, allowed = self._parameters(context)
        scope = inventory.latest_scope(context.audit.id)
        if scope is None:
            raise self._validation_error(
                "scope_not_confirmed",
                "Protocol audits require a confirmed authorized scope",
            )
        assets = inventory.list_assets(
            audit_id=context.audit.id,
            limit=10_000,
            offset=0,
            include_services=False,
        ).items
        services = inventory.list_services(
            audit_id=context.audit.id,
            limit=10_000,
            offset=0,
        ).items
        if not services:
            raise self._validation_error(
                "inventory_empty",
                "Protocol audits require persisted inventory services",
            )

        self._ensure_not_cancelled(context)
        self._progress(context, 12, "matching_services", "Matching services")
        work = match_work(
            registry=self.registry,
            assets=assets,
            services=services,
            scope=scope,
            allowed_modules=allowed,
        )
        executor = ProtocolModuleRunner(
            runner=runner,
            settings=context.settings,
            evidence_store=context.evidence_store,
            observation_store=store,
        )
        runs: list[dict[str, Any]] = []
        total = max(len(work), 1)
        for index, item in enumerate(work):
            self._ensure_not_cancelled(context)
            module = self.registry.get(item.module)
            percentage = 15 + int(75 * index / total)
            self._progress(
                context,
                min(percentage, 90),
                f"auditing_{module.name}",
                (
                    f"Auditing {module.name} on "
                    f"{item.target.address}:{item.target.port}"
                ),
            )
            run = executor.run(
                module,
                item.target,
                audit_id=context.audit.id,
                job_id=context.job.id,
                cancellation_token=context.cancellation_token,
            )
            runs.append(run.model_dump(mode="json"))

        self._ensure_not_cancelled(context)
        self._progress(
            context,
            94,
            "summarizing",
            "Summarizing protocol observations",
        )
        observation_count = store.count(context.audit.id)
        summary = {
            "schema": "protocol-audit-summary",
            "schema_version": 1,
            "profile": profile.value,
            "modules": sorted({item.module for item in work}) or list(allowed or self.registry.default_names),
            "matched_services": len(work),
            "module_runs": len(runs),
            "observations": observation_count,
            "unavailable_tools": [
                run["tool"]
                for run in runs
                if run.get("skipped") and not run.get("available")
            ],
        }
        document = {
            "schema": "protocol-audit-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "profile": profile.value,
            "confirmed_scope_id": scope.id,
            "interface": scope.interface,
            "runs": runs,
            "summary": summary,
        }
        artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="protocol_audit_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="protocol-audit-result",
            schema_version=1,
        )
        self.logger.info(
            "protocol audit completed",
            extra={
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "component": "protocol_audit",
                "matched_services": len(work),
                "observations": observation_count,
            },
        )
        return HandlerResult(
            result_reference=artifact.id,
            summary={
                **summary,
                "result_reference": artifact.id,
            },
        )

    def _parameters(
        self,
        context: HandlerContext,
    ) -> tuple[ProtocolAuditProfile, frozenset[str] | None]:
        parameters = context.job.parameters
        try:
            profile = ProtocolAuditProfile(str(parameters.get("profile", "default")))
        except ValueError as exc:
            raise self._validation_error(
                "invalid_profile",
                "Protocol audit profile is invalid",
            ) from exc
        raw_modules = parameters.get("modules")
        allowed = None
        if raw_modules is not None:
            if not isinstance(raw_modules, list) or not raw_modules:
                raise self._validation_error(
                    "invalid_modules",
                    "modules must be a non-empty list of module names",
                )
            allowed = frozenset(str(item) for item in raw_modules)
            unknown = sorted(allowed - set(self.registry.default_names))
            gated = [name for name in sorted(allowed) if self.registry.is_gated(name)]
            if gated:
                raise self._validation_error(
                    "module_gated",
                    "Requested protocol modules are gated off",
                    details={"modules": gated},
                )
            if unknown:
                raise self._validation_error(
                    "unknown_module",
                    "Requested protocol modules are not available",
                    details={"modules": unknown},
                )
        return profile, allowed

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
            raise JobCancelled("Protocol audit was cancelled")

    @staticmethod
    def _validation_error(
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=code,
                category=ErrorCategory.VALIDATION,
                message=message,
                component="protocol_audit",
                details=details or {},
            )
        )
