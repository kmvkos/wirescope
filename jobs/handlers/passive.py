"""Durable passive discovery handler."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from engine.passive import PassivePipeline
from engine.passive_models import (
    CaptureStatus,
    PassiveResult,
    PipelineErrorCode,
)
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import (
    ErrorCategory,
    JobError,
    JobProgress,
    RetentionClass,
)
from jobs.registry import HandlerContext, HandlerResult


class PassiveDiscoveryHandler:
    def __init__(
        self,
        pipeline_factory: Callable[[], PassivePipeline] | None = None,
        inventory_factory: (
            Callable[[HandlerContext], InventoryService] | None
        ) = None,
    ) -> None:
        self.pipeline_factory = pipeline_factory or PassivePipeline
        self.inventory_factory = inventory_factory or (
            lambda context: InventoryService(
                context.evidence_store.database,
                context.settings,
                context.evidence_store,
            )
        )

    def execute(self, context: HandlerContext) -> HandlerResult:
        interface = str(
            context.job.parameters.get("interface")
            or context.job.target
            or ""
        )
        duration = int(
            context.job.parameters.get(
                "duration_seconds",
                context.settings.passive_duration_default,
            )
        )
        pipeline = self.pipeline_factory()
        result = pipeline.run(
            interface,
            duration,
            retain_capture=context.settings.passive_retain_capture,
            cancellation_token=context.cancellation_token,
            progress_callback=lambda percentage, stage, message: (
                context.report_progress(
                    JobProgress(
                        percentage=percentage,
                        stage=stage,
                        message=message,
                    )
                )
            ),
        )

        if (
            context.cancellation_token.cancelled
            or result.capture.status == CaptureStatus.CANCELLED
        ):
            self._cleanup_retained_capture(pipeline, result)
            raise JobCancelled("Passive discovery cancelled")

        if result.capture.status == CaptureStatus.FAILED:
            self._cleanup_retained_capture(pipeline, result)
            raise self._pipeline_error(result)
        if any(
            error.code
            in {
                PipelineErrorCode.DECODE_FAILED,
                PipelineErrorCode.MALFORMED_INPUT,
            }
            for error in result.errors
        ):
            self._cleanup_retained_capture(pipeline, result)
            raise self._pipeline_error(result)

        artifact_references: list[str] = []
        if (
            context.settings.passive_retain_capture
            and result.capture.pcap_path
        ):
            capture_artifact = context.evidence_store.import_file(
                audit_id=context.audit.id,
                job_id=context.job.id,
                artifact_type="packet_capture",
                source=Path(result.capture.pcap_path),
                content_type="application/vnd.tcpdump.pcap",
                extension=".pcap",
                retention_class=RetentionClass.AUDIT,
            )
            artifact_references.append(capture_artifact.id)
            self._cleanup_retained_capture(pipeline, result)

        document = {
            "schema": "passive-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "artifacts": artifact_references,
            "result": result.model_dump(mode="json"),
        }
        result_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="passive_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="passive-result",
            schema_version=1,
        )
        hosts_persisted = self.inventory_factory(context).ingest_passive_from_audit(
            context.audit.id,
            job_id=context.job.id,
        )
        return HandlerResult(
            result_reference=result_artifact.id,
            summary=self._summary(result, result_artifact.id, hosts_persisted),
        )

    @staticmethod
    def _summary(
        result: PassiveResult,
        result_reference: str,
        hosts_persisted: int = 0,
    ) -> dict[str, Any]:
        visibility = None
        if result.assessment is not None and result.assessment.visibility is not None:
            visibility = result.assessment.visibility.value
        return {
            "schema": "passive-summary",
            "schema_version": 1,
            "result_reference": result_reference,
            "interface": result.interface,
            "frame_count": result.capture.frame_count,
            "hosts_persisted": hosts_persisted,
            "visibility": visibility,
            "detected_sensors": sorted(
                name
                for name, sensor in result.sensors.items()
                if sensor.detected
            ),
            "warning_count": len(result.capture.warnings),
            "error_count": len(result.errors),
        }

    @staticmethod
    def _pipeline_error(result: PassiveResult) -> JobExecutionError:
        pipeline_error = result.errors[0] if result.errors else None
        tool_error = (
            result.capture.tool_result.error.code.value
            if result.capture.tool_result.error
            else None
        )
        category = {
            "missing_binary": ErrorCategory.TOOL_MISSING,
            "permission_denied": ErrorCategory.PERMISSION,
            "timeout": ErrorCategory.TIMEOUT,
        }.get(tool_error, ErrorCategory.INTERNAL)
        return JobExecutionError(
            JobError(
                code=(
                    pipeline_error.code.value
                    if pipeline_error
                    else "passive_discovery_failed"
                ),
                category=category,
                message=(
                    pipeline_error.message
                    if pipeline_error
                    else "Passive discovery failed"
                ),
                component=(
                    pipeline_error.component
                    if pipeline_error
                    else "passive_handler"
                ),
                retryable=bool(
                    pipeline_error.retryable if pipeline_error else False
                ),
                details={"tool_error": tool_error},
            )
        )

    @staticmethod
    def _cleanup_retained_capture(
        pipeline: PassivePipeline,
        result: PassiveResult,
    ) -> None:
        if result.capture.pcap_path:
            pipeline.capture_provider.cleanup(result.capture, force=True)
