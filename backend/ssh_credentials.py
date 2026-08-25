"""Ephemeral credential hand-off for read-only SSH topology enrichment.

Private keys and known_hosts material never enter SQLite job parameters or
persisted topology evidence.  The API writes a 0600 consume-once spool file;
the worker deletes it on success, failure and cancellation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
from typing import Any

from config.settings import Settings


_REF_RE = re.compile(r"^[0-9a-f]{32}$")


class SshCredentialReferenceError(ValueError):
    pass


class SshCredentialSpool:
    def __init__(self, settings: Settings) -> None:
        self.root = (settings.runtime_dir / "ssh-topology-credentials").resolve()

    def put(self, payload: dict[str, Any]) -> str:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        reference = uuid.uuid4().hex
        final_path = self._path(reference)
        fd, temporary = tempfile.mkstemp(prefix=".ssh-topology-", dir=self.root)
        temporary_path = Path(temporary)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, final_path)
            final_path.chmod(0o600)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            temporary_path.unlink(missing_ok=True)
            raise
        return reference

    def consume(self, reference: str) -> dict[str, Any]:
        path = self._path(reference)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SshCredentialReferenceError("SSH topology credential reference is missing or expired") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise SshCredentialReferenceError("SSH topology credential reference could not be read") from exc
        if not isinstance(payload, dict):
            raise SshCredentialReferenceError("SSH topology credential reference is invalid")
        return payload

    def delete(self, reference: str) -> None:
        self._path(reference).unlink(missing_ok=True)

    def cleanup_stale(self, *, max_age_seconds: int) -> int:
        if not self.root.is_dir():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(60, max_age_seconds))
        removed = 0
        for path in self.root.iterdir():
            if not path.is_file():
                continue
            try:
                modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if modified < cutoff:
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed

    def _path(self, reference: str) -> Path:
        if not _REF_RE.fullmatch(str(reference or "")):
            raise SshCredentialReferenceError("Invalid SSH topology credential reference")
        path = (self.root / f"{reference}.json").resolve()
        if not path.is_relative_to(self.root):
            raise SshCredentialReferenceError("Unsafe SSH topology credential reference")
        return path
