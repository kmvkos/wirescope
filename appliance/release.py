"""Checksums for release artifacts. Signing is documented when a key is present."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path


DEFAULT_HASH = "sha256"


@dataclass(frozen=True)
class ChecksumRecord:
    algorithm: str
    digest: str
    relative_path: str


def file_digest(path: Path, *, algorithm: str = DEFAULT_HASH) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def checksum_paths(
    paths: list[Path],
    *,
    root: Path,
    algorithm: str = DEFAULT_HASH,
) -> list[ChecksumRecord]:
    records: list[ChecksumRecord] = []
    for path in sorted(paths, key=lambda item: str(item)):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        records.append(
            ChecksumRecord(
                algorithm=algorithm,
                digest=file_digest(path, algorithm=algorithm),
                relative_path=relative,
            )
        )
    return records


def render_checksums(records: list[ChecksumRecord]) -> str:
    lines = [
        f"{item.algorithm}  {item.digest}  {item.relative_path}"
        for item in records
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def default_release_paths(project_root: Path) -> list[Path]:
    candidates = [
        project_root / "pyproject.toml",
        project_root / "packaging" / "install.sh",
        project_root / "packaging" / "upgrade.sh",
        *sorted((project_root / "packaging" / "systemd").glob("*.service")),
        *sorted((project_root / "packaging" / "inventory").glob("*")),
        *sorted((project_root / "packaging" / "proxy").glob("*")),
        project_root / "packaging" / "kiosk" / "kiosk.sh",
    ]
    return [path for path in candidates if path.is_file()]
