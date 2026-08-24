"""Typed active-discovery profiles loaded from a bounded declarative file."""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from config.settings import Settings
from engine.scope import ActiveProfile


class ProfileConfigError(ValueError):
    pass


class ActiveScanProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ActiveProfile
    timing: str = Field(pattern=r"^T[0-4]$")
    tcp_top_ports: int | None = Field(default=None, ge=1, le=65_535)
    tcp_ports: str | None = Field(default=None, max_length=64)
    udp_ports: tuple[int, ...] = ()
    service_detection: bool = False
    version_intensity: int | None = Field(default=None, ge=0, le=9)
    os_detection: bool = False
    run_tcp_scan: bool = True
    run_udp_scan: bool = False
    timeout_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_ports(self) -> "ActiveScanProfile":
        if len(self.udp_ports) > 256:
            raise ValueError("udp_ports exceeds the 256-port profile limit")
        if any(port < 1 or port > 65_535 for port in self.udp_ports):
            raise ValueError("udp_ports contains an invalid port")
        if self.tcp_ports not in {None, "1-65535"}:
            raise ValueError("tcp_ports accepts only the bounded full-range value 1-65535")
        return self


class _ProfileDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timing: str = Field(pattern=r"^T[0-4]$")
    tcp_top_ports: int | None = Field(default=None, ge=1, le=65_535)
    tcp_ports: str | None = Field(default=None, max_length=64)
    udp_ports: tuple[int, ...] = ()
    service_detection: bool = False
    version_intensity: int | None = Field(default=None, ge=0, le=9)
    os_detection: bool = False
    run_tcp_scan: bool = True
    run_udp_scan: bool = False


_DEFAULTS = {
    "discovery": {
        "timing": "T3",
        "tcp_top_ports": 100,
        "tcp_ports": None,
        "udp_ports": [],
        "service_detection": False,
        "version_intensity": None,
        "os_detection": False,
        "run_tcp_scan": False,
        "run_udp_scan": False,
    },
    "standard": {
        "timing": "T3",
        "tcp_top_ports": 1_000,
        "tcp_ports": None,
        "udp_ports": [53, 67, 68, 69, 111, 123, 137, 161, 162, 500, 623, 1900, 4500, 5353, 5355],
        "service_detection": True,
        "version_intensity": 5,
        "os_detection": True,
        "run_tcp_scan": True,
        "run_udp_scan": True,
    },
    "deep": {
        "timing": "T3",
        "tcp_top_ports": None,
        "tcp_ports": "1-65535",
        "udp_ports": [7, 9, 19, 37, 49, 53, 67, 68, 69, 88, 111, 123, 135, 137, 138, 139, 161, 162, 177, 389, 427, 443, 445, 500, 514, 520, 623, 631, 1434, 1645, 1646, 1701, 1812, 1813, 1900, 2049, 3478, 4500, 5060, 5353, 5355, 5683, 10000, 17185, 20031],
        "service_detection": True,
        "version_intensity": 7,
        "os_detection": True,
        "run_tcp_scan": True,
        "run_udp_scan": True,
    },
}


def _profile_file(settings: Settings) -> Path:
    override = os.getenv("WIRESCOPE_ACTIVE_PROFILES_FILE", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return settings.project_root / "config" / "active_profiles.json"


def _load_documents(settings: Settings) -> dict[str, _ProfileDocument]:
    path = _profile_file(settings)
    raw = _DEFAULTS
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileConfigError(f"Cannot read active scan profiles from {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ProfileConfigError("Active scan profile file must contain a JSON object")
        raw = loaded

    expected = {item.value for item in ActiveProfile}
    if set(raw) != expected:
        raise ProfileConfigError(
            f"Active scan profiles must define exactly: {', '.join(sorted(expected))}"
        )
    try:
        return {name: _ProfileDocument.model_validate(value) for name, value in raw.items()}
    except Exception as exc:
        raise ProfileConfigError(f"Invalid active scan profile configuration: {exc}") from exc


def profile_for(profile: ActiveProfile, settings: Settings) -> ActiveScanProfile:
    document = _load_documents(settings)[profile.value]
    timeout_by_profile = {
        ActiveProfile.DISCOVERY: settings.nmap_discovery_timeout_seconds,
        ActiveProfile.STANDARD: settings.nmap_standard_timeout_seconds,
        ActiveProfile.DEEP: settings.nmap_deep_timeout_seconds,
    }
    return ActiveScanProfile(
        name=profile,
        timeout_seconds=timeout_by_profile[profile],
        **document.model_dump(),
    )


def profile_catalog(settings: Settings) -> dict[str, dict]:
    documents = _load_documents(settings)
    return {
        name: {
            **document.model_dump(mode="json"),
            "timeout_seconds": profile_for(ActiveProfile(name), settings).timeout_seconds,
        }
        for name, document in documents.items()
    }
