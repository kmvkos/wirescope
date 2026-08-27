"""Durable enqueue semantics for post-capture traffic analysis."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from jobs.models import AuditStatus, JobStatus
from persistence.database import Database
from persistence.models import ArtifactModel, AuditModel, JobEventModel, JobModel
from traffic_analysis import ANALYZER_VERSION


class TrafficAnalysisSourceNotReady(RuntimeError):
    pass


class TrafficAnalysisPcapUnavailable(RuntimeError):
    """Raised when the retained source PCAP disappeared before enqueue."""


class TrafficAnalysisJobService:
    """Create/reuse analysis jobs without weakening general audit transitions.

    Packet capture audits commonly end as ``cancelled`` when an operator presses
    Stop after collecting enough traffic. Analysis is explicitly allowed to
    reopen that hidden capture audit because it performs no new network action.
    The ordinary JobService create_job contract remains unchanged for all other
    audit workflows.

    Completed results are reused only when they were produced by the current
    analyzer version. This lets an operator re-run an old retained PCAP after a
    WireScope diagnostics upgrade while preserving idempotency within a version.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    def enqueue(
        self,
        *,
        audit_id: str,
        source_capture_job_id: str,
        pcap_artifact_id: str,
    ) -> str:
        with self.database.immediate_session() as session:
            audit = session.get(AuditModel, audit_id)
            if audit is None:
                raise LookupError(f"Audit not found: {audit_id}")

            capture = session.get(JobModel, source_capture_job_id)
            if (
                capture is None
                or capture.audit_id != audit_id
                or capture.type != "packet_capture"
            ):
                raise LookupError(
                    f"Capture session not found: {source_capture_job_id}"
                )

            # This check intentionally lives inside the same IMMEDIATE
            # transaction that creates/reuses the analysis job. The API does a
            # friendly pre-check too, but DELETE /captures/{id}/pcap may race
            # with that read. Manual PCAP deletion removes the artifact row in
            # its own IMMEDIATE transaction, so only one side can win: either
            # analysis is queued first (and deletion then sees an active job),
            # or deletion commits first and enqueue rejects the missing source.
            pcap = session.get(ArtifactModel, pcap_artifact_id)
            if (
                pcap is None
                or pcap.audit_id != audit_id
                or pcap.job_id != source_capture_job_id
                or pcap.artifact_type != "packet_capture"
            ):
                raise TrafficAnalysisPcapUnavailable(
                    "Capture PCAP has been deleted or expired"
                )

            existing = session.scalars(
                select(JobModel)
                .where(
                    JobModel.audit_id == audit_id,
                    JobModel.type == "traffic_analysis",
                )
                .order_by(JobModel.created_at.desc())
            ).all()
            for job in existing:
                parameters = dict(job.parameters or {})
                if (
                    parameters.get("source_capture_job_id") == source_capture_job_id
                    and parameters.get("pcap_artifact_id") == pcap_artifact_id
                    and parameters.get("analyzer_version") == ANALYZER_VERSION
                    and JobStatus(job.status) in {
                        JobStatus.QUEUED,
                        JobStatus.RUNNING,
                        JobStatus.COMPLETED,
                    }
                ):
                    return job.id

            active = session.scalars(
                select(JobModel).where(
                    JobModel.audit_id == audit_id,
                    JobModel.status.in_((JobStatus.QUEUED.value, JobStatus.RUNNING.value)),
                )
            ).all()
            if active:
                raise TrafficAnalysisSourceNotReady(
                    "Capture audit still has an active job"
                )

            current = AuditStatus(audit.status)
            if current not in {
                AuditStatus.COMPLETED,
                AuditStatus.CANCELLED,
                AuditStatus.FAILED,
                AuditStatus.INTERRUPTED,
            }:
                raise TrafficAnalysisSourceNotReady(
                    f"Capture audit is not ready for analysis: {current.value}"
                )

            audit.status = AuditStatus.RUNNING.value
            audit.finished_at = None
            job = JobModel(
                id=str(uuid.uuid4()),
                audit_id=audit_id,
                type="traffic_analysis",
                status=JobStatus.QUEUED.value,
                priority=0,
                progress=0,
                stage="queued",
                message="Traffic analysis queued",
                target=source_capture_job_id,
                parameters={
                    "source_capture_job_id": source_capture_job_id,
                    "pcap_artifact_id": pcap_artifact_id,
                    "analyzer_version": ANALYZER_VERSION,
                },
                cancel_requested=False,
                attempt=0,
                resource_key=f"pcap-analysis:{pcap_artifact_id}",
                resource_group="traffic_analysis",
                resource_limit=1,
            )
            session.add(job)
            session.flush()
            session.add(
                JobEventModel(
                    audit_id=audit_id,
                    job_id=job.id,
                    event_type="job_queued",
                    stage="queued",
                    progress=0,
                    message="Traffic analysis queued",
                    details={
                        "source_capture_job_id": source_capture_job_id,
                        "pcap_artifact_id": pcap_artifact_id,
                        "analyzer_version": ANALYZER_VERSION,
                    },
                )
            )
            return job.id
