"""Operator listen/record capture handler. Always retains the pcap as evidence."""

from collections.abc import Callable
from pathlib import Path
import time

from engine.interfaces import InterfaceService, InterfaceValidationError
from engine.passive_models import CaptureResult, CaptureStatus
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import (
    ErrorCategory,
    JobError,
    JobProgress,
    RetentionClass,
)
from jobs.registry import HandlerContext, HandlerResult
from providers.bpf import BpfFilterError, normalize_bpf_filter
from providers.capture import CaptureProvider, CaptureStats, PCAP_HEADER_BYTES


class PacketCaptureHandler:
    def __init__(
        self,
        capture_factory: Callable[[HandlerContext], CaptureProvider] | None = None,
        interface_factory: (
            Callable[[HandlerContext], InterfaceService] | None
        ) = None,
    ) -> None:
        self.capture_factory = capture_factory or (
            lambda context: CaptureProvider(settings=context.settings)
        )
        self.interface_factory = interface_factory or (
            lambda context: InterfaceService(settings=context.settings)
        )

    def execute(self, context: HandlerContext) -> HandlerResult:
        interface_name = str(
            context.job.parameters.get("interface")
            or context.job.target
            or ""
        )
        if not interface_name:
            raise JobExecutionError(
                JobError(
                    code="interface_required",
                    category=ErrorCategory.VALIDATION,
                    message="Listen capture requires an interface",
                    component="packet_capture",
                )
            )
        try:
            filter_text = normalize_bpf_filter(
                context.job.parameters.get("filter"),
                max_length=context.settings.listen_filter_max_length,
            )
        except BpfFilterError as exc:
            raise JobExecutionError(
                JobError(
                    code=exc.code,
                    category=ErrorCategory.VALIDATION,
                    message=exc.message,
                    component="packet_capture",
                )
            ) from exc

        duration = context.job.parameters.get("duration_seconds")
        if duration is None:
            duration = context.settings.listen_duration_default
        duration = int(duration)
        filesize = context.job.parameters.get("max_filesize_kb")
        if filesize is None:
            filesize = context.settings.listen_max_filesize_kb_default
        filesize = int(filesize)

        context.report_progress(
            JobProgress(
                percentage=1,
                stage="capturing",
                message="Starting packet capture",
            )
        )
        interfaces = self.interface_factory(context)
        try:
            interface = interfaces.validate(interface_name)
        except InterfaceValidationError as exc:
            raise JobExecutionError(
                JobError(
                    code=exc.code.value,
                    category=ErrorCategory.VALIDATION,
                    message=exc.message,
                    component="packet_capture",
                )
            ) from exc
        provider = self.capture_factory(context)
        last_percentage = 1
        last_emit = 0.0

        def on_stats(stats: CaptureStats) -> None:
            nonlocal last_percentage, last_emit
            now = time.monotonic()
            percentage = max(last_percentage, min(99, stats.percentage or last_percentage))
            if percentage == last_percentage and now - last_emit < 1.0:
                return
            last_percentage = percentage
            last_emit = now
            frames = stats.frame_count if stats.frame_count is not None else 0
            context.report_progress(
                JobProgress(
                    percentage=percentage,
                    stage="capturing",
                    message=(
                        f"{frames} frames, {stats.byte_count} bytes, "
                        f"{int(stats.elapsed_seconds)}s"
                    ),
                )
            )

        try:
            result = provider.record(
                interface,
                duration_seconds=duration,
                max_filesize_kb=filesize,
                bpf_filter=filter_text,
                cancellation_token=context.cancellation_token,
                progress_callback=on_stats,
            )
        except (ValueError, BpfFilterError) as exc:
            message = exc.message if isinstance(exc, BpfFilterError) else str(exc)
            raise JobExecutionError(
                JobError(
                    code=getattr(exc, "code", "invalid_listen_limits"),
                    category=ErrorCategory.VALIDATION,
                    message=message,
                    component="packet_capture",
                )
            ) from exc

        cancelled = (
            context.cancellation_token.cancelled
            or result.status == CaptureStatus.CANCELLED
        )
        if result.status == CaptureStatus.FAILED:
            provider.cleanup(result, force=True)
            raise self._capture_error(result)

        pcap_path = Path(result.pcap_path) if result.pcap_path else None
        has_pcap = bool(
            pcap_path is not None
            and pcap_path.is_file()
            and pcap_path.stat().st_size >= PCAP_HEADER_BYTES
        )
        if cancelled and not has_pcap:
            provider.cleanup(result, force=True)
            raise JobCancelled("Packet capture cancelled")

        context.report_progress(
            JobProgress(
                percentage=max(last_percentage, 99),
                stage="saving",
                message="Saving capture",
            )
        )
        artifact_references: list[str] = []
        pcap_artifact_id = None
        pcap_bytes = pcap_path.stat().st_size if has_pcap and pcap_path else 0
        if has_pcap and pcap_path is not None:
            capture_artifact = context.evidence_store.import_file(
                audit_id=context.audit.id,
                job_id=context.job.id,
                artifact_type="packet_capture",
                source=pcap_path,
                content_type="application/vnd.tcpdump.pcap",
                extension=".pcap",
                retention_class=RetentionClass.AUDIT,
            )
            artifact_references.append(capture_artifact.id)
            pcap_artifact_id = capture_artifact.id
            pcap_bytes = capture_artifact.size
        provider.cleanup(result, force=True)

        document = {
            "schema": "packet-capture-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "interface": interface.name,
            "filter": filter_text,
            "promiscuous": True,
            "duration_seconds": duration,
            "max_filesize_kb": filesize,
            "frame_count": result.frame_count,
            "byte_count": pcap_bytes,
            "dropped_packets": result.dropped_packets,
            "pcap_artifact_id": pcap_artifact_id,
            "artifacts": artifact_references,
            "warnings": list(result.warnings),
            "stopped_by_operator": cancelled,
        }
        result_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="packet_capture_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="packet-capture-result",
            schema_version=1,
        )
        summary = {
            "schema": "packet-capture-summary",
            "schema_version": 1,
            "result_reference": result_artifact.id,
            "interface": interface.name,
            "filter": filter_text,
            "promiscuous": True,
            "duration_seconds": duration,
            "max_filesize_kb": filesize,
            "frame_count": result.frame_count,
            "byte_count": pcap_bytes,
            "pcap_artifact_id": pcap_artifact_id,
            "pcap_bytes": pcap_bytes,
            "warning_count": len(result.warnings),
            "stopped_by_operator": cancelled,
        }
        if cancelled:
            raise JobCancelled(
                "Packet capture cancelled",
                result_reference=result_artifact.id,
                summary=summary,
            )
        return HandlerResult(
            result_reference=result_artifact.id,
            summary=summary,
        )

    @staticmethod
    def _capture_error(result: CaptureResult) -> JobExecutionError:
        pipeline_error = result.errors[0] if result.errors else None
        tool_error = (
            result.tool_result.error.code.value
            if result.tool_result and result.tool_result.error
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
                    else "packet_capture_failed"
                ),
                category=category,
                message=(
                    pipeline_error.message
                    if pipeline_error
                    else "Packet capture failed"
                ),
                component=(
                    pipeline_error.component
                    if pipeline_error
                    else "packet_capture"
                ),
                retryable=bool(
                    pipeline_error.retryable if pipeline_error else False
                ),
                details={"tool_error": tool_error},
            )
        )
