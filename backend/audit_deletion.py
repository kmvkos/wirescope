"""Safe full-audit deletion and evidence cleanup.

Deleting an audit is intentionally stronger than deleting a generated report:
all durable audit state and all files stored under that audit's evidence
directory are removed. Active audits are never deleted; the operator must stop
or finish their queued/running work first.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from sqlalchemy import delete, func, select

from jobs.models import AuditStatus, JobStatus
from jobs.service import EntityNotFound
from persistence.database import Database
from persistence.models import ArtifactModel, AuditModel, JobModel
from storage.evidence import EvidenceStore


class AuditBusy(RuntimeError):
    """Raised when an audit still owns queued or running work."""

    def __init__(self, audit_id: str, active_jobs: int) -> None:
        self.audit_id = audit_id
        self.active_jobs = active_jobs
        super().__init__(
            f"Audit {audit_id} has {active_jobs} queued/running job(s)"
        )


@dataclass(frozen=True)
class AuditDeletionResult:
    audit_id: str
    artifact_count: int
    deleted_files: int
    evidence_directory_removed: bool
    file_cleanup_pending: bool


class AuditDeletionService:
    def __init__(self, database: Database, evidence: EvidenceStore) -> None:
        self.database = database
        self.evidence = evidence

    def delete(self, audit_id: str) -> AuditDeletionResult:
        """Delete one inactive audit and every durable row owned by it.

        SQLite foreign-key cascades remove jobs/events, inventory, observations,
        findings, reports, scopes and artifact metadata in the same transaction.
        Files are deleted after the transaction so a filesystem failure cannot
        roll back or partially resurrect relational audit state.
        """
        with self.database.immediate_session() as session:
            audit = session.get(AuditModel, audit_id)
            if audit is None:
                raise EntityNotFound(f"Audit not found: {audit_id}")

            active_jobs = (
                session.scalar(
                    select(func.count())
                    .select_from(JobModel)
                    .where(
                        JobModel.audit_id == audit_id,
                        JobModel.status.in_(
                            (JobStatus.QUEUED.value, JobStatus.RUNNING.value)
                        ),
                    )
                )
                or 0
            )
            if active_jobs or audit.status == AuditStatus.RUNNING.value:
                raise AuditBusy(audit_id, int(active_jobs))

            artifact_count = (
                session.scalar(
                    select(func.count())
                    .select_from(ArtifactModel)
                    .where(ArtifactModel.audit_id == audit_id)
                )
                or 0
            )
            session.execute(delete(AuditModel).where(AuditModel.id == audit_id))

        audit_dir = self._audit_directory(audit_id)
        deleted_files = 0
        cleanup_pending = False
        removed_directory = False
        try:
            if audit_dir.exists():
                deleted_files = sum(1 for path in audit_dir.rglob("*") if path.is_file())
                shutil.rmtree(audit_dir)
            removed_directory = not audit_dir.exists()
        except OSError:
            # Logical deletion is already complete. The maintenance/orphan path
            # can retry stale files later; surface this state to diagnostics/UI.
            cleanup_pending = True
            removed_directory = False

        return AuditDeletionResult(
            audit_id=audit_id,
            artifact_count=int(artifact_count),
            deleted_files=deleted_files,
            evidence_directory_removed=removed_directory,
            file_cleanup_pending=cleanup_pending,
        )

    def _audit_directory(self, audit_id: str) -> Path:
        root = self.evidence.root.resolve()
        candidate = (root / audit_id).resolve()
        if not candidate.is_relative_to(root):
            raise ValueError("Audit evidence path escaped the controlled root")
        return candidate
