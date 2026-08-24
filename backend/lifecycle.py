"""Operational lifecycle helpers: storage visibility and conservative cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import os
from pathlib import Path
import shutil
from typing import Any

from sqlalchemy import func, or_, select, text

from config.settings import Settings
from jobs.maintenance import MaintenanceService
from persistence.database import Database
from persistence.models import ArtifactModel, AuditModel, JobModel, utc_now
from storage.evidence import EvidenceStore


@dataclass(frozen=True)
class RetentionPolicy:
    temporary_hours: int
    debug_days: int
    packet_capture_days: int
    raw_provider_days: int

    def as_dict(self) -> dict[str, int]:
        return {
            "temporary_hours": self.temporary_hours,
            "debug_days": self.debug_days,
            "packet_capture_days": self.packet_capture_days,
            "raw_provider_days": self.raw_provider_days,
        }


class LifecycleService:
    """Keep maintenance explicit and preserve normalized audit history by default."""

    RAW_TYPES = frozenset({"packet_capture", "nmap_xml", "protocol_tool_output"})

    def __init__(
        self,
        database: Database,
        evidence_store: EvidenceStore,
        settings: Settings,
    ) -> None:
        self.database = database
        self.evidence_store = evidence_store
        self.settings = settings
        self.maintenance = MaintenanceService(database, evidence_store, settings)

    def policy(self) -> RetentionPolicy:
        return RetentionPolicy(
            temporary_hours=_positive_env("WIRESCOPE_TEMP_ARTIFACT_RETENTION_HOURS", 24),
            debug_days=_positive_env("WIRESCOPE_DEBUG_RETENTION_DAYS", 7),
            packet_capture_days=_positive_env("WIRESCOPE_PCAP_RETENTION_DAYS", 30),
            raw_provider_days=_positive_env("WIRESCOPE_RAW_EVIDENCE_RETENTION_DAYS", 90),
        )

    def status(self) -> dict[str, Any]:
        policy = self.policy()
        data_usage = _disk_usage(self.settings.data_dir)
        evidence_bytes, evidence_files = _tree_usage(self.evidence_store.root)
        database_bytes = (
            self.settings.database_path.stat().st_size
            if self.settings.database_path.is_file()
            else 0
        )
        with self.database.session() as session:
            audits = session.scalar(select(func.count()).select_from(AuditModel)) or 0
            jobs = session.scalar(select(func.count()).select_from(JobModel)) or 0
            artifacts = session.scalar(select(func.count()).select_from(ArtifactModel)) or 0
            artifact_bytes = session.scalar(select(func.coalesce(func.sum(ArtifactModel.size), 0))) or 0
            quick_check = session.execute(text("PRAGMA quick_check")).scalar_one_or_none()
        candidates = self._candidate_snapshot(include_raw=True, policy=policy)
        return {
            "database": {
                "path": str(self.settings.database_path),
                "bytes": int(database_bytes),
                "revision": self.database.current_revision(),
                "quick_check": quick_check,
            },
            "storage": {
                "data_dir": str(self.settings.data_dir),
                "evidence_dir": str(self.evidence_store.root),
                "evidence_files": evidence_files,
                "evidence_bytes": evidence_bytes,
                "artifact_rows": int(artifacts),
                "artifact_bytes": int(artifact_bytes),
                **data_usage,
            },
            "records": {
                "audits": int(audits),
                "jobs": int(jobs),
                "artifacts": int(artifacts),
            },
            "retention": {
                "policy": policy.as_dict(),
                "automatic_raw_deletion": False,
                "note": (
                    "Normalized audit data and reports are retained. Raw evidence is "
                    "deleted only by an explicit confirmed maintenance request."
                ),
                "candidates": candidates,
            },
        }

    def cleanup(
        self,
        *,
        confirm: bool,
        include_raw: bool,
    ) -> dict[str, Any]:
        policy = self.policy()
        preview = self._candidate_snapshot(include_raw=include_raw, policy=policy)
        if not confirm:
            return {
                "confirmed": False,
                "include_raw": include_raw,
                "policy": policy.as_dict(),
                "would_delete": preview,
            }

        safe = self.maintenance.run_startup_cleanup()
        safe["terminal_job_events"] = self.maintenance.prune_terminal_job_events()
        deleted = self._delete_candidates(include_raw=include_raw, policy=policy)
        return {
            "confirmed": True,
            "include_raw": include_raw,
            "policy": policy.as_dict(),
            "housekeeping": safe,
            "deleted": deleted,
        }

    def _candidate_snapshot(
        self,
        *,
        include_raw: bool,
        policy: RetentionPolicy,
    ) -> dict[str, Any]:
        rows = self._candidates(include_raw=include_raw, policy=policy)
        by_type: dict[str, dict[str, int]] = {}
        for row in rows:
            bucket = by_type.setdefault(row.artifact_type, {"count": 0, "bytes": 0})
            bucket["count"] += 1
            bucket["bytes"] += int(row.size)
        return {
            "count": len(rows),
            "bytes": sum(int(row.size) for row in rows),
            "by_type": by_type,
        }

    def _candidates(
        self,
        *,
        include_raw: bool,
        policy: RetentionPolicy,
    ) -> list[ArtifactModel]:
        now = utc_now()
        conditions = [
            (
                (ArtifactModel.retention_class == "temporary")
                & (ArtifactModel.created_at < now - timedelta(hours=policy.temporary_hours))
            ),
            (
                (ArtifactModel.retention_class == "debug")
                & (ArtifactModel.created_at < now - timedelta(days=policy.debug_days))
            ),
        ]
        if include_raw:
            conditions.extend(
                [
                    (
                        (ArtifactModel.artifact_type == "packet_capture")
                        & (
                            ArtifactModel.created_at
                            < now - timedelta(days=policy.packet_capture_days)
                        )
                    ),
                    (
                        ArtifactModel.artifact_type.in_(("nmap_xml", "protocol_tool_output"))
                        & (
                            ArtifactModel.created_at
                            < now - timedelta(days=policy.raw_provider_days)
                        )
                    ),
                ]
            )
        with self.database.session() as session:
            return list(
                session.scalars(
                    select(ArtifactModel)
                    .where(or_(*conditions))
                    .order_by(ArtifactModel.created_at)
                ).all()
            )

    def _delete_candidates(
        self,
        *,
        include_raw: bool,
        policy: RetentionPolicy,
    ) -> dict[str, Any]:
        rows = self._candidates(include_raw=include_raw, policy=policy)
        ids: list[str] = []
        removed_bytes = 0
        removed_files = 0
        root = self.evidence_store.root.resolve()
        for row in rows:
            candidate = (root / row.relative_path).resolve()
            if not candidate.is_relative_to(root):
                continue
            if candidate.is_file():
                removed_bytes += candidate.stat().st_size
                candidate.unlink(missing_ok=True)
                removed_files += 1
            ids.append(row.id)
        if ids:
            with self.database.session() as session, session.begin():
                models = session.scalars(
                    select(ArtifactModel).where(ArtifactModel.id.in_(ids))
                ).all()
                for model in models:
                    session.delete(model)
        return {
            "artifact_rows": len(ids),
            "files": removed_files,
            "bytes": removed_bytes,
        }


def _positive_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = int(raw)
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _tree_usage(root: Path) -> tuple[int, int]:
    if not root.is_dir():
        return 0, 0
    total = 0
    files = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            total += path.stat().st_size
            files += 1
        except FileNotFoundError:
            continue
    return total, files


def _disk_usage(path: Path) -> dict[str, int]:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    usage = shutil.disk_usage(path)
    return {
        "filesystem_total_bytes": usage.total,
        "filesystem_used_bytes": usage.used,
        "filesystem_free_bytes": usage.free,
    }
