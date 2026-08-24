"""Production paths, ownership, and directory modes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PROJECT_ROOT = Path("/opt/wirescope")
DEFAULT_DATA_DIR = Path("/var/lib/wirescope")
DEFAULT_ETC_DIR = Path("/etc/wirescope")
DEFAULT_SYSTEMD_DIR = Path("/etc/systemd/system")
DEFAULT_JOURNALD_DIR = Path("/etc/systemd/journald.conf.d")
SERVICE_USER = "wirescope"
SERVICE_GROUP = "wirescope"
WIRESHARK_GROUP = "wireshark"
DUMPCAP_PATH = Path("/usr/bin/dumpcap")
DUMPCAP_CAPS = "cap_net_admin,cap_net_raw=eip"
DUMPCAP_MODE = 0o750
ENV_FILE_NAME = "wirescope.env"
ENV_FILE_MODE = 0o640
PASSWORD_FILE_MODE = 0o600


@dataclass(frozen=True)
class DirectorySpec:
    path: Path
    mode: int
    owner: str
    group: str


@dataclass(frozen=True)
class InstallPaths:
    project_root: Path = DEFAULT_PROJECT_ROOT
    data_dir: Path = DEFAULT_DATA_DIR
    etc_dir: Path = DEFAULT_ETC_DIR
    systemd_dir: Path = DEFAULT_SYSTEMD_DIR
    journald_dir: Path = DEFAULT_JOURNALD_DIR
    venv_dir: Path = field(default_factory=lambda: DEFAULT_PROJECT_ROOT / ".venv")
    dumpcap_path: Path = DUMPCAP_PATH
    service_user: str = SERVICE_USER
    service_group: str = SERVICE_GROUP

    @property
    def database_path(self) -> Path:
        return self.data_dir / "wirescope.db"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def runtime_dir(self) -> Path:
        return self.data_dir / "runtime"

    @property
    def capture_dir(self) -> Path:
        return self.runtime_dir / "captures"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def env_file(self) -> Path:
        return self.etc_dir / ENV_FILE_NAME

    @property
    def bootstrap_dir(self) -> Path:
        return self.runtime_dir / "bootstrap"

    @property
    def python(self) -> Path:
        return self.venv_dir / "bin" / "python"

    @property
    def pip(self) -> Path:
        return self.venv_dir / "bin" / "pip"

    @property
    def alembic(self) -> Path:
        return self.venv_dir / "bin" / "alembic"

    def directories(self) -> tuple[DirectorySpec, ...]:
        user = self.service_user
        group = self.service_group
        return (
            DirectorySpec(self.data_dir, 0o750, user, group),
            DirectorySpec(self.evidence_dir, 0o700, user, group),
            DirectorySpec(self.runtime_dir, 0o700, user, group),
            DirectorySpec(self.capture_dir, 0o700, user, group),
            DirectorySpec(self.backup_dir, 0o700, user, group),
            DirectorySpec(self.bootstrap_dir, 0o700, user, group),
            DirectorySpec(self.etc_dir, 0o750, "root", group),
        )


def production_env_text(paths: InstallPaths, *, bind_host: str, bind_port: int) -> str:
    return "\n".join(
        [
            "# WireScope appliance environment. Do not put passwords here.",
            f"WIRESCOPE_ROOT={paths.project_root}",
            f"WIRESCOPE_FRONTEND_DIR={paths.project_root / 'frontend'}",
            f"WIRESCOPE_DATA_DIR={paths.data_dir}",
            f"WIRESCOPE_DATABASE_PATH={paths.database_path}",
            f"WIRESCOPE_EVIDENCE_DIR={paths.evidence_dir}",
            f"WIRESCOPE_RUNTIME_DIR={paths.runtime_dir}",
            f"WIRESCOPE_CAPTURE_DIR={paths.capture_dir}",
            "WIRESCOPE_DOCS_ENABLED=false",
            f"WIRESCOPE_BIND_HOST={bind_host}",
            f"WIRESCOPE_BIND_PORT={bind_port}",
            "WIRESCOPE_SESSION_COOKIE_SECURE=false",
            "WIRESCOPE_DUMPCAP_BINARY=/usr/bin/dumpcap",
            "WIRESCOPE_TSHARK_BINARY=/usr/bin/tshark",
            "WIRESCOPE_NMAP_BINARY=/usr/bin/nmap",
            "",
        ]
    )
