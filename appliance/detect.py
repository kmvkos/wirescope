"""Detect Debian-family OS and amd64 versus arm64."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
from typing import Mapping


class UnsupportedPlatformError(ValueError):
    pass


@dataclass(frozen=True)
class Platform:
    family: str
    distro_id: str
    version_id: str
    pretty_name: str
    arch: str
    machine: str
    raspberry_pi: bool

    @property
    def supported(self) -> bool:
        return self.family == "debian" and self.arch in {"amd64", "arm64"}


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def debian_family(os_release: Mapping[str, str]) -> bool:
    distro_id = os_release.get("ID", "").lower()
    like = os_release.get("ID_LIKE", "").lower().split()
    return distro_id == "debian" or "debian" in like


def normalize_arch(machine: str) -> str:
    lowered = machine.strip().lower()
    if lowered in {"x86_64", "amd64"}:
        return "amd64"
    if lowered in {"aarch64", "arm64"}:
        return "arm64"
    if lowered in {"armv7l", "armhf", "armv8l"}:
        return "arm"
    return lowered or "unknown"


def is_raspberry_pi(
    os_release: Mapping[str, str],
    *,
    model_text: str = "",
    device_tree_model: str = "",
) -> bool:
    combined = " ".join(
        [
            os_release.get("ID", ""),
            os_release.get("VERSION_CODENAME", ""),
            os_release.get("PRETTY_NAME", ""),
            model_text,
            device_tree_model,
        ]
    ).lower()
    return "raspberry" in combined or "raspbian" in combined


def detect_platform(
    *,
    os_release_text: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    machine: str | None = None,
    model_text: str = "",
    device_tree_path: Path = Path("/proc/device-tree/model"),
) -> Platform:
    if os_release_text is None:
        if not os_release_path.is_file():
            raise UnsupportedPlatformError("missing /etc/os-release")
        os_release_text = os_release_path.read_text(encoding="utf-8")
    os_release = parse_os_release(os_release_text)
    if not debian_family(os_release):
        raise UnsupportedPlatformError(
            f"unsupported OS family: {os_release.get('ID', 'unknown')}"
        )
    resolved_machine = machine if machine is not None else platform.machine()
    arch = normalize_arch(resolved_machine)
    if arch not in {"amd64", "arm64"}:
        raise UnsupportedPlatformError(f"unsupported architecture: {arch}")
    tree_model = ""
    if not model_text and device_tree_path.is_file():
        tree_model = device_tree_path.read_text(encoding="utf-8", errors="replace")
    return Platform(
        family="debian",
        distro_id=os_release.get("ID", "debian").lower(),
        version_id=os_release.get("VERSION_ID", ""),
        pretty_name=os_release.get("PRETTY_NAME", ""),
        arch=arch,
        machine=resolved_machine,
        raspberry_pi=is_raspberry_pi(
            os_release,
            model_text=model_text,
            device_tree_model=tree_model,
        ),
    )
