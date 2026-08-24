"""Atomic filesystem artifacts with durable SQLite metadata."""

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid
from typing import Any

from sqlalchemy import select

from config.settings import Settings
from jobs.errors import JobExecutionError
from jobs.models import (
    ArtifactRecord,
    ErrorCategory,
    JobError,
    RetentionClass,
)
from persistence.database import Database
from persistence.models import ArtifactModel


class EvidenceStore:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.root = settings.evidence_dir.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def put_json(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        artifact_type: str,
        document: dict[str, Any],
        retention_class: RetentionClass,
        schema_name: str,
        schema_version: int,
    ) -> ArtifactRecord:
        payload = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return self.put_bytes(
            audit_id=audit_id,
            job_id=job_id,
            artifact_type=artifact_type,
            payload=payload,
            content_type="application/json",
            extension=".json",
            retention_class=retention_class,
            schema_name=schema_name,
            schema_version=schema_version,
        )

    def put_bytes(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        artifact_type: str,
        payload: bytes,
        content_type: str,
        extension: str,
        retention_class: RetentionClass,
        schema_name: str | None = None,
        schema_version: int | None = None,
    ) -> ArtifactRecord:
        artifact_id = str(uuid.uuid4())
        final_path: Path | None = None
        temp_path: Path | None = None
        try:
            final_path, relative_path = self._artifact_path(
                audit_id,
                job_id,
                artifact_id,
                extension,
            )
            temp_path = final_path.with_name(
                f"{final_path.name}.tmp-{uuid.uuid4()}"
            )
            with temp_path.open("xb") as handle:
                os.chmod(temp_path, 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, final_path)
            self._fsync_directory(final_path.parent)
            return self._register(
                artifact_id=artifact_id,
                audit_id=audit_id,
                job_id=job_id,
                artifact_type=artifact_type,
                relative_path=relative_path,
                content_type=content_type,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                retention_class=retention_class,
                schema_name=schema_name,
                schema_version=schema_version,
            )
        except Exception as exc:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            if final_path is not None:
                final_path.unlink(missing_ok=True)
            if isinstance(exc, JobExecutionError):
                raise
            raise self._storage_error(
                "artifact_write_failed",
                f"Could not persist artifact: {exc}",
            ) from exc

    def import_file(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        artifact_type: str,
        source: Path,
        content_type: str,
        extension: str,
        retention_class: RetentionClass,
    ) -> ArtifactRecord:
        artifact_id = str(uuid.uuid4())
        final_path: Path | None = None
        temp_path: Path | None = None
        digest = hashlib.sha256()
        size = 0
        try:
            final_path, relative_path = self._artifact_path(
                audit_id,
                job_id,
                artifact_id,
                extension,
            )
            temp_path = final_path.with_name(
                f"{final_path.name}.tmp-{uuid.uuid4()}"
            )
            with source.open("rb") as input_file, temp_path.open("xb") as output:
                os.chmod(temp_path, 0o600)
                while chunk := input_file.read(1024 * 1024):
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, final_path)
            self._fsync_directory(final_path.parent)
            return self._register(
                artifact_id=artifact_id,
                audit_id=audit_id,
                job_id=job_id,
                artifact_type=artifact_type,
                relative_path=relative_path,
                content_type=content_type,
                size=size,
                sha256=digest.hexdigest(),
                retention_class=retention_class,
                schema_name=None,
                schema_version=None,
            )
        except Exception as exc:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            if final_path is not None:
                final_path.unlink(missing_ok=True)
            if isinstance(exc, JobExecutionError):
                raise
            raise self._storage_error(
                "artifact_import_failed",
                f"Could not import artifact: {exc}",
            ) from exc

    def read_bytes(self, artifact: ArtifactRecord) -> bytes:
        path = self.path_for(artifact)
        try:
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != artifact.sha256:
                raise ValueError("Artifact checksum mismatch")
            return payload
        except Exception as exc:
            raise self._storage_error(
                "artifact_read_failed",
                f"Could not read artifact: {exc}",
            ) from exc

    def read_json(self, artifact: ArtifactRecord) -> dict[str, Any]:
        try:
            value = json.loads(self.read_bytes(artifact))
            if not isinstance(value, dict):
                raise ValueError("Artifact root must be an object")
            return value
        except JobExecutionError:
            raise
        except Exception as exc:
            raise self._storage_error(
                "artifact_read_failed",
                f"Could not read artifact: {exc}",
            ) from exc

    def path_for(self, artifact: ArtifactRecord) -> Path:
        candidate = (self.root / artifact.relative_path).resolve()
        if not candidate.is_relative_to(self.root):
            raise self._storage_error(
                "unsafe_artifact_path",
                "Artifact path escaped the controlled storage root",
            )
        return candidate

    def cleanup_stale_temporary_files(
        self,
        *,
        older_than_seconds: int | None = None,
    ) -> int:
        threshold = datetime.now(timezone.utc) - timedelta(
            seconds=(
                older_than_seconds
                if older_than_seconds is not None
                else self.settings.temp_file_max_age_seconds
            )
        )
        removed = 0
        for path in self.root.rglob("*.tmp-*"):
            modified = datetime.fromtimestamp(
                path.stat().st_mtime,
                tz=timezone.utc,
            )
            if modified < threshold:
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def cleanup_orphan_files(
        self,
        *,
        older_than_seconds: int | None = None,
    ) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=(
                older_than_seconds
                if older_than_seconds is not None
                else self.settings.temp_file_max_age_seconds
            )
        )
        with self.database.session() as session:
            known = set(session.scalars(select(ArtifactModel.relative_path)))
        removed = 0
        for path in self._artifact_files():
            relative = str(path.relative_to(self.root))
            modified = datetime.fromtimestamp(
                path.stat().st_mtime,
                tz=timezone.utc,
            )
            if relative not in known and modified < cutoff:
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def _artifact_files(self) -> Iterable[Path]:
        for path in self.root.rglob("*"):
            if path.is_file() and ".tmp-" not in path.name:
                yield path

    def _register(
        self,
        *,
        artifact_id: str,
        audit_id: str,
        job_id: str | None,
        artifact_type: str,
        relative_path: str,
        content_type: str,
        size: int,
        sha256: str,
        retention_class: RetentionClass,
        schema_name: str | None,
        schema_version: int | None,
    ) -> ArtifactRecord:
        model = ArtifactModel(
            id=artifact_id,
            audit_id=audit_id,
            job_id=job_id,
            artifact_type=artifact_type,
            relative_path=relative_path,
            content_type=content_type,
            size=size,
            sha256=sha256,
            retention_class=retention_class.value,
            schema_name=schema_name,
            schema_version=schema_version,
        )
        with self.database.session() as session, session.begin():
            session.add(model)
        return ArtifactRecord(
            id=model.id,
            audit_id=model.audit_id,
            job_id=model.job_id,
            artifact_type=model.artifact_type,
            relative_path=model.relative_path,
            content_type=model.content_type,
            size=model.size,
            sha256=model.sha256,
            created_at=model.created_at,
            retention_class=RetentionClass(model.retention_class),
            schema_name=model.schema_name,
            schema_version=model.schema_version,
        )

    def _artifact_path(
        self,
        audit_id: str,
        job_id: str | None,
        artifact_id: str,
        extension: str,
    ) -> tuple[Path, str]:
        self._validate_identifier(audit_id)
        if job_id is not None:
            self._validate_identifier(job_id)
        self._validate_identifier(artifact_id)
        if not extension.startswith(".") or "/" in extension:
            raise self._storage_error(
                "invalid_artifact_extension",
                "Artifact extension is invalid",
            )
        directory = self.root / audit_id / (job_id or "audit")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        final_path = directory / f"{artifact_id}{extension}"
        return final_path, str(final_path.relative_to(self.root))

    @staticmethod
    def _validate_identifier(value: str) -> None:
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise EvidenceStore._storage_error(
                "invalid_artifact_identifier",
                "Artifact identifiers must be UUIDs",
            ) from exc
        if str(parsed) != value:
            raise EvidenceStore._storage_error(
                "invalid_artifact_identifier",
                "Artifact identifiers must use canonical UUID format",
            )

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _storage_error(code: str, message: str) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=code,
                category=ErrorCategory.STORAGE,
                message=message,
                component="evidence_store",
                retryable=False,
            )
        )
