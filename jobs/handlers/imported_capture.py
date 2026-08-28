"""Durable worker path for operator-supplied PCAP/PCAPNG captures."""

from __future__ import annotations

import os

from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from storage.pcap_import import (
    PcapImportValidationError,
    import_staging_path,
    inspect_pcap_file,
    materialize_capture_file,
    sanitize_original_filename,
)


def _max_import_bytes() -> int:
    raw = os.getenv("WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB", "256").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB must be an integer") from exc
    if not 1 <= value <= 4096:
        raise RuntimeError("WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB must be 1..4096")
    return value * 1024 * 1024


class ImportedPacketCaptureHandler:
    def execute(self, context: HandlerContext) -> HandlerResult:
        token = str(context.job.parameters.get("staging_token") or "")
        original_name = sanitize_original_filename(
            context.job.parameters.get("original_filename")
        )
        expected_sha256 = str(context.job.parameters.get("upload_sha256") or "")
        expected_size = int(context.job.parameters.get("uploaded_bytes") or 0)
        expected_compression = context.job.parameters.get("source_compression")
        max_bytes = _max_import_bytes()
        staging = None
        normalized = None
        try:
            try:
                staging = import_staging_path(context.evidence_store.root, token)
                info = inspect_pcap_file(staging, max_bytes=max_bytes)
            except PcapImportValidationError as exc:
                raise self._validation_error(exc) from exc

            if expected_size and info.size != expected_size:
                raise self._validation_error(
                    PcapImportValidationError(
                        "pcap_import_size_mismatch",
                        "Uploaded PCAP size changed before worker processing",
                    )
                )
            if expected_sha256 and info.sha256 != expected_sha256:
                raise self._validation_error(
                    PcapImportValidationError(
                        "pcap_import_checksum_mismatch",
                        "Uploaded PCAP checksum changed before worker processing",
                    )
                )
            if expected_compression != info.compression:
                raise self._validation_error(
                    PcapImportValidationError(
                        "pcap_import_compression_mismatch",
                        "Uploaded PCAP compression changed before worker processing",
                    )
                )

            context.report_progress(
                JobProgress(
                    percentage=35,
                    stage="validating_import",
                    message="Validated imported PCAP",
                )
            )
            if context.cancellation_token.cancelled:
                return HandlerResult()

            source = staging
            if info.compression:
                context.report_progress(
                    JobProgress(
                        percentage=55,
                        stage="normalizing_import",
                        message="Decompressing imported PCAP",
                    )
                )
                normalized = staging.with_name(f"{staging.name}.normalized")
                try:
                    source = materialize_capture_file(
                        staging,
                        normalized,
                        info=info,
                        max_bytes=max_bytes,
                    )
                except PcapImportValidationError as exc:
                    raise self._validation_error(exc) from exc

            context.report_progress(
                JobProgress(
                    percentage=70,
                    stage="saving",
                    message="Saving imported PCAP",
                )
            )
            capture_artifact = context.evidence_store.import_file(
                audit_id=context.audit.id,
                job_id=context.job.id,
                artifact_type="packet_capture",
                source=source,
                content_type=info.content_type,
                extension=info.extension,
                retention_class=RetentionClass.AUDIT,
            )
            if (
                capture_artifact.size != info.capture_size
                or capture_artifact.sha256 != info.capture_sha256
            ):
                raise self._validation_error(
                    PcapImportValidationError(
                        "pcap_import_normalization_mismatch",
                        "Canonical capture changed while being stored",
                    )
                )

            document = {
                "schema": "packet-capture-result",
                "schema_version": 1,
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "source_origin": "imported",
                "source_compression": info.compression,
                "original_filename": original_name,
                "capture_format": info.format,
                "uploaded_bytes": info.size,
                "upload_sha256": info.sha256,
                "capture_sha256": info.capture_sha256,
                "interface": None,
                "filter": None,
                "promiscuous": False,
                "duration_seconds": None,
                "max_filesize_kb": None,
                "frame_count": None,
                "byte_count": capture_artifact.size,
                "dropped_packets": None,
                "pcap_artifact_id": capture_artifact.id,
                "artifacts": [capture_artifact.id],
                "warnings": [],
                "stopped_by_operator": False,
                "network_io_performed": False,
                "active_scope_authorized": False,
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
            return HandlerResult(
                result_reference=result_artifact.id,
                summary={
                    "schema": "packet-capture-summary",
                    "schema_version": 1,
                    "result_reference": result_artifact.id,
                    "source_origin": "imported",
                    "source_compression": info.compression,
                    "original_filename": original_name,
                    "capture_format": info.format,
                    "uploaded_bytes": info.size,
                    "capture_sha256": info.capture_sha256,
                    "interface": None,
                    "filter": None,
                    "promiscuous": False,
                    "duration_seconds": None,
                    "max_filesize_kb": None,
                    "frame_count": None,
                    "byte_count": capture_artifact.size,
                    "pcap_artifact_id": capture_artifact.id,
                    "pcap_bytes": capture_artifact.size,
                    "warning_count": 0,
                    "stopped_by_operator": False,
                    "network_io_performed": False,
                    "active_scope_authorized": False,
                },
            )
        finally:
            if normalized is not None:
                normalized.unlink(missing_ok=True)
            if staging is not None:
                staging.unlink(missing_ok=True)

    @staticmethod
    def _validation_error(exc: PcapImportValidationError) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=exc.code,
                category=ErrorCategory.VALIDATION,
                message=exc.message,
                component="pcap_import",
                retryable=False,
            )
        )
