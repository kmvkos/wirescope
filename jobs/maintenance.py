"""Conservative maintenance that never deletes audit records implicitly."""

from datetime import datetime, timedelta, timezone
import shutil

from sqlalchemy import delete, select

from config.settings import Settings
from jobs.models import JobStatus
from persistence.database import Database
from persistence.models import JobEventModel, JobModel, utc_now
from storage.evidence import EvidenceStore


class MaintenanceService:
    def __init__(
        self,
        database: Database,
        evidence_store: EvidenceStore,
        settings: Settings,
    ) -> None:
        self.database = database
        self.evidence_store = evidence_store
        self.settings = settings

    def run_startup_cleanup(self) -> dict[str, int]:
        return {
            "stale_temporary_files": (
                self.evidence_store.cleanup_stale_temporary_files()
            ),
            "orphan_files": self.evidence_store.cleanup_orphan_files(),
            "stale_capture_directories": (
                self._cleanup_stale_capture_directories()
            ),
        }

    def prune_terminal_job_events(self) -> int:
        cutoff = utc_now() - timedelta(
            days=self.settings.job_event_retention_days
        )
        terminal = tuple(
            status.value
            for status in JobStatus
            if status.terminal
        )
        with self.database.session() as session, session.begin():
            job_ids = select(JobModel.id).where(
                JobModel.status.in_(terminal),
                JobModel.finished_at < cutoff,
            )
            result = session.execute(
                delete(JobEventModel).where(
                    JobEventModel.job_id.in_(job_ids),
                    JobEventModel.created_at < cutoff,
                )
            )
            return result.rowcount or 0

    def _cleanup_stale_capture_directories(self) -> int:
        capture_root = self.settings.capture_dir
        if not capture_root.is_dir():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=self.settings.temp_file_max_age_seconds
        )
        removed = 0
        for directory in capture_root.iterdir():
            if not directory.is_dir() or not directory.name.startswith(
                "wirescope_"
            ):
                continue
            modified = datetime.fromtimestamp(
                directory.stat().st_mtime,
                tz=timezone.utc,
            )
            if modified < cutoff:
                shutil.rmtree(directory)
                removed += 1
        return removed
