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


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    project_root: Path
    frontend_dir: Path
    data_dir: Path
    docs_enabled: bool


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
        docs_enabled=_env_bool("WIRESCOPE_DOCS_ENABLED", True),
    )
