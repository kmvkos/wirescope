"""Safe deletion of retained raw PCAP while preserving capture history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from jobs.models import JobStatus
from jobs.service import EntityNotFound
from persistence.database import Database
from persistence.models import ArtifactModel, AuditModel, JobModel
from storage.evidence import EvidenceStore


class CapturePcapBusy(RuntimeError):
    """Raised when raw PCAP is still in use by an active capture-audit job."""


class CapturePcapDeletionSafetyError(RuntimeError):
    """Raised when a stored artifact path escapes the configured evidence root."""


@dataclass(frozen=True)
class CapturePcapDeletionResult:
    job_id: str
    audit_id: str
    deleted: bool
    already_absent: bool
    artifact_count: int
    pcap_bytes: int
    file_cleanup_pending: int


class CapturePcapDeletionService:
    """Remove only raw ``packet_capture`` artifacts for one capture job.

    The capture job, immutable ``capture_result`` metadata, completed Traffic
    Analysis artifacts and any downstream Correlated Assessment results are
    intentionally retained.  This makes deletion a storage/privacy operation,
    not history deletion.
    """

    def __init__(self, database: Database, evidence: EvidenceStore) -> None:
        self.database = database
        self.evidence = evidence

    def _safe_path(self, relative_path: str) -> Path:
        root = self.evidence.root.resolve(strict=False)
        candidate = (root / relative_path).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise CapturePcapDeletionSafetyError(
                "PCAP artifact path escapes the evidence root"
            ) from exc
        return candidate

    def delete(self, job_id: str, *, actor: str | None = None) -> CapturePcapDeletionResult:
        paths: list[Path] = []
        artifact_count = 0
        historical_bytes = 0
        changed = False
        already_absent = False

        with self.database.immediate_session() as session:
            job = session.get(JobModel, job_id)
            if job is None or job.type != "packet_capture":
                raise EntityNotFound(f"Capture session not found: {job_id}")

            active = session.scalars(
                select(JobModel).where(
                    JobModel.audit_id == job.audit_id,
                    JobModel.status.in_(
                        (JobStatus.QUEUED.value, JobStatus.RUNNING.value)
                    ),
                )
            ).all()
            if active:
                raise CapturePcapBusy(
                    "Finish or stop the capture/analysis before deleting its PCAP"
                )

            audit = session.get(AuditModel, job.audit_id)
            if audit is None:
                raise EntityNotFound(f"Audit not found: {job.audit_id}")

            artifacts = session.scalars(
                select(ArtifactModel).where(
                    ArtifactModel.audit_id == job.audit_id,
                    ArtifactModel.job_id == job.id,
                    ArtifactModel.artifact_type == "packet_capture",
                )
            ).all()

            # Validate every path before mutating the database.  A malformed
            # metadata row must never turn this endpoint into an arbitrary-file
            # deletion primitive.
            paths = [self._safe_path(row.relative_path) for row in artifacts]
            artifact_count = len(artifacts)
            historical_bytes = sum(int(row.size or 0) for row in artifacts)

            summary = dict(audit.summary or {})
            had_reference = bool(summary.get("pcap_artifact_id"))
            already_absent = not artifacts
            changed = bool(artifacts or had_reference)

            for row in artifacts:
                session.delete(row)

            if had_reference:
                summary["pcap_artifact_id"] = None
            if changed:
                summary.setdefault(
                    "pcap_deleted_at",
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                )
                if actor:
                    summary.setdefault("pcap_deleted_by", actor)
                audit.summary = summary

        cleanup_pending = 0
        for path in paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                # Metadata is already gone, matching the existing audit/report
                # deletion contract. Diagnostics can surface the orphaned file
                # for manual cleanup without exposing it through the API.
                cleanup_pending += 1

        return CapturePcapDeletionResult(
            job_id=job_id,
            audit_id=job.audit_id,
            deleted=changed,
            already_absent=already_absent,
            artifact_count=artifact_count,
            pcap_bytes=historical_bytes,
            file_cleanup_pending=cleanup_pending,
        )
