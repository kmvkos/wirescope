"""SQLite and evidence backup/restore for the local appliance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
import tempfile


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupArchive:
    directory: Path
    database_path: Path
    evidence_path: Path | None
    created_at: str


def sqlite_backup(source: Path, destination: Path) -> Path:
    if not source.is_file():
        raise BackupError(f"database not found: {source}")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    source_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        dest_conn = sqlite3.connect(temporary)
        try:
            source_conn.backup(dest_conn)
            dest_conn.execute("PRAGMA integrity_check")
            dest_conn.commit()
        finally:
            dest_conn.close()
    finally:
        source_conn.close()
    temporary.replace(destination)
    destination.chmod(0o600)
    return destination


def restore_sqlite(archive: Path, destination: Path) -> Path:
    if not archive.is_file():
        raise BackupError(f"backup not found: {archive}")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent,
        prefix="restore-",
        suffix=".db",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
    try:
        shutil.copy2(archive, temp_path)
        conn = sqlite3.connect(temp_path)
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        finally:
            conn.close()
        if rows != [("ok",)]:
            raise BackupError("backup failed integrity_check")
        temp_path.replace(destination)
        destination.chmod(0o600)
    finally:
        if temp_path.exists() and temp_path != destination:
            temp_path.unlink(missing_ok=True)
    return destination


def create_backup(
    *,
    database_path: Path,
    evidence_dir: Path,
    backup_dir: Path,
    include_evidence: bool = True,
) -> BackupArchive:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = backup_dir / stamp
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = sqlite_backup(database_path, target / "wirescope.db")
    evidence_copy: Path | None = None
    if include_evidence and evidence_dir.is_dir():
        evidence_copy = target / "evidence"
        shutil.copytree(evidence_dir, evidence_copy, dirs_exist_ok=False)
    return BackupArchive(
        directory=target,
        database_path=database,
        evidence_path=evidence_copy,
        created_at=stamp,
    )


def restore_backup(
    archive: BackupArchive | Path,
    *,
    database_path: Path,
    evidence_dir: Path,
    restore_evidence: bool = True,
) -> None:
    if isinstance(archive, Path):
        database = archive / "wirescope.db" if archive.is_dir() else archive
        evidence = archive / "evidence" if archive.is_dir() else None
    else:
        database = archive.database_path
        evidence = archive.evidence_path
    restore_sqlite(database, database_path)
    if restore_evidence and evidence is not None and Path(evidence).is_dir():
        if evidence_dir.exists():
            shutil.rmtree(evidence_dir)
        shutil.copytree(evidence, evidence_dir)
