"""Centralized, environment-aware application settings."""

from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path


def _env_path(name: str, default: Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    return int(raw_value) if raw_value is not None else default


def _env_list(name: str) -> tuple[str, ...]:
    raw_value = os.getenv(name, "")
    return tuple(
        item.strip()
        for item in raw_value.split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    project_root: Path
    frontend_dir: Path
    data_dir: Path
    capture_dir: Path
    docs_enabled: bool
    allowed_interfaces: tuple[str, ...]
    allow_loopback: bool
    require_interface_up: bool
    passive_duration_min: int
    passive_duration_max: int
    passive_duration_default: int
    capture_max_packets: int
    capture_max_filesize_kb: int
    dumpcap_binary: str
    tshark_binary: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    default_root = Path(__file__).resolve().parents[1]
    project_root = _env_path("WIRESCOPE_ROOT", default_root)

    return Settings(
        app_name="WireScope",
        app_version="0.1.0",
        project_root=project_root,
        frontend_dir=_env_path(
            "WIRESCOPE_FRONTEND_DIR",
            project_root / "frontend",
        ),
        data_dir=_env_path(
            "WIRESCOPE_DATA_DIR",
            project_root / "data",
        ),
        capture_dir=_env_path(
            "WIRESCOPE_CAPTURE_DIR",
            project_root / "data" / "runtime" / "captures",
        ),
        docs_enabled=_env_bool("WIRESCOPE_DOCS_ENABLED", True),
        allowed_interfaces=_env_list("WIRESCOPE_ALLOWED_INTERFACES"),
        allow_loopback=_env_bool("WIRESCOPE_ALLOW_LOOPBACK", False),
        require_interface_up=_env_bool(
            "WIRESCOPE_REQUIRE_INTERFACE_UP",
            True,
        ),
        passive_duration_min=_env_int("WIRESCOPE_PASSIVE_DURATION_MIN", 5),
        passive_duration_max=_env_int("WIRESCOPE_PASSIVE_DURATION_MAX", 300),
        passive_duration_default=_env_int(
            "WIRESCOPE_PASSIVE_DURATION_DEFAULT",
            30,
        ),
        capture_max_packets=_env_int(
            "WIRESCOPE_CAPTURE_MAX_PACKETS",
            50_000,
        ),
        capture_max_filesize_kb=_env_int(
            "WIRESCOPE_CAPTURE_MAX_FILESIZE_KB",
            16_384,
        ),
        dumpcap_binary=os.getenv("WIRESCOPE_DUMPCAP_BINARY", "dumpcap"),
        tshark_binary=os.getenv("WIRESCOPE_TSHARK_BINARY", "tshark"),
    )
