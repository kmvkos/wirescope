"""Durable analysis of a retained operator capture."""

from __future__ import annotations

from pathlib import Path

from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from persistence.models import ArtifactModel
from traffic_analysis.analyzer import TrafficAnalyzer
from traffic_analysis.render import render_markdown, render_text


class TrafficAnalysisHandler:
    def execute(self, context: HandlerContext) -> HandlerResult:
        pcap_artifact_id = str(context.job.parameters.get("pcap_artifact_id") or "")
        source_capture_job_id = str(
            context.job.parameters.get("source_capture_job_id") or context.job.target or ""
        )
        if not pcap_artifact_id or not source_capture_job_id:
            raise JobExecutionError(
                JobError(
                    code="traffic_analysis_source_required",
                    category=ErrorCategory.VALIDATION,
                    message="Traffic analysis requires a retained capture artifact",
                    component="traffic_analysis",
                )
            )

        context.report_progress(
            JobProgress(
                percentage=2,
                stage="loading_pcap",
                message="Проверяем сохранённый PCAP",
            )
        )
        with context.evidence_store.database.session() as session:
            artifact = session.get(ArtifactModel, pcap_artifact_id)
            if artifact is None:
                raise JobExecutionError(
                    JobError(
                        code="pcap_artifact_not_found",
                        category=ErrorCategory.VALIDATION,
                        message="Stored PCAP artifact is not registered",
                        component="traffic_analysis",
                    )
                )
            if artifact.audit_id != context.audit.id:
                raise JobExecutionError(
                    JobError(
                        code="pcap_audit_mismatch",
                        category=ErrorCategory.VALIDATION,
                        message="PCAP artifact does not belong to the capture audit",
                        component="traffic_analysis",
                    )
                )
            if artifact.job_id != source_capture_job_id:
                raise JobExecutionError(
                    JobError(
                        code="pcap_capture_job_mismatch",
                        category=ErrorCategory.VALIDATION,
                        message="PCAP artifact does not belong to the source capture job",
                        component="traffic_analysis",
                    )
                )
            if artifact.artifact_type != "packet_capture":
                raise JobExecutionError(
                    JobError(
                        code="invalid_pcap_artifact",
                        category=ErrorCategory.VALIDATION,
                        message="Traffic analysis source is not a packet capture artifact",
                        component="traffic_analysis",
                    )
                )
            relative_path = artifact.relative_path
            pcap_size = artifact.size
            pcap_sha256 = artifact.sha256

        root = context.evidence_store.root
        pcap_path = (root / relative_path).resolve()
        if not pcap_path.is_relative_to(root):
            raise JobExecutionError(
                JobError(
                    code="unsafe_pcap_path",
                    category=ErrorCategory.INTERNAL,
                    message="Stored PCAP path escaped the controlled evidence root",
                    component="traffic_analysis",
                )
            )

        def progress(percentage: int, message: str) -> None:
            context.report_progress(
                JobProgress(
                    percentage=max(3, min(79, int(percentage))),
                    stage="analyzing_pcap",
                    message=message,
                )
            )

        analyzer = TrafficAnalyzer(settings=context.settings)
        document = analyzer.analyze(
            Path(pcap_path),
            source={
                "capture_audit_id": context.audit.id,
                "capture_job_id": source_capture_job_id,
                "pcap_artifact_id": pcap_artifact_id,
                "pcap_sha256": pcap_sha256,
                "pcap_bytes": pcap_size,
                "interface": context.audit.interface,
                "filter": (context.audit.scope or {}).get("filter"),
            },
            cancellation_token=context.cancellation_token,
            progress=progress,
        )

        context.report_progress(
            JobProgress(
                percentage=82,
                stage="rendering_analysis",
                message="Формируем понятный текстовый разбор",
            )
        )
        text_payload = render_text(document).encode("utf-8")
        markdown_payload = render_markdown(document).encode("utf-8")
        text_artifact = context.evidence_store.put_bytes(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="traffic_analysis_text",
            payload=text_payload,
            content_type="text/plain; charset=utf-8",
            extension=".txt",
            retention_class=RetentionClass.AUDIT,
            schema_name="traffic-analysis-text",
            schema_version=1,
        )
        markdown_artifact = context.evidence_store.put_bytes(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="traffic_analysis_markdown",
            payload=markdown_payload,
            content_type="text/markdown; charset=utf-8",
            extension=".md",
            retention_class=RetentionClass.AUDIT,
            schema_name="traffic-analysis-markdown",
            schema_version=1,
        )
        document["artifacts"] = {
            "text_artifact_id": text_artifact.id,
            "markdown_artifact_id": markdown_artifact.id,
        }

        context.report_progress(
            JobProgress(
                percentage=94,
                stage="saving_analysis",
                message="Сохраняем результат анализа и communication graph",
            )
        )
        result_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="traffic_analysis_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="traffic-analysis",
            schema_version=1,
        )
        summary = document.get("summary") or {}
        return HandlerResult(
            result_reference=result_artifact.id,
            summary={
                "traffic_analysis_job_id": context.job.id,
                "traffic_analysis_reference": result_artifact.id,
                "traffic_analysis_text_artifact_id": text_artifact.id,
                "traffic_analysis_markdown_artifact_id": markdown_artifact.id,
                "traffic_analysis_frame_count": summary.get("frame_count", 0),
                "traffic_analysis_conversations": summary.get("conversation_count", 0),
                "traffic_analysis_observations": len(document.get("observations") or []),
            },
        )
