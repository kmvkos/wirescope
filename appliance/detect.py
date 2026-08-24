"""Detect Linux family via apt/dnf/yum/zypper and amd64 versus arm64.

Raspberry Pi is optional hardware, not a required OS.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import shutil
from typing import Mapping


class UnsupportedPlatformError(ValueError):
    pass


SUPPORTED_FAMILIES = frozenset({"debian", "rhel", "suse"})
SUPPORTED_ARCHES = frozenset({"amd64", "arm64"})
SUPPORTED_PACKAGE_MANAGERS = frozenset({"apt", "dnf", "yum", "zypper"})

DEBIAN_IDS = frozenset(
    {"debian", "ubuntu", "raspbian", "linuxmint", "pop", "elementary"}
)
RHEL_IDS = frozenset(
    {
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "ol",
        "amzn",
        "eurolinux",
        "scientific",
        "mageia",
    }
)
SUSE_IDS = frozenset(
    {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled", "suse"}
)

_FAMILY_MANAGERS: dict[str, tuple[str, ...]] = {
    "debian": ("apt",),
    "rhel": ("dnf", "yum"),
    "suse": ("zypper",),
}

_MANAGER_BINARIES: tuple[tuple[str, str], ...] = (
    ("apt-get", "apt"),
    ("dnf", "dnf"),
    ("yum", "yum"),
    ("zypper", "zypper"),
)


@dataclass(frozen=True)
class Platform:
    family: str
    package_manager: str
    distro_id: str
    version_id: str
    pretty_name: str
    arch: str
    machine: str
    raspberry_pi: bool

    @property
    def supported(self) -> bool:
        return (
            self.family in SUPPORTED_FAMILIES
            and self.package_manager in SUPPORTED_PACKAGE_MANAGERS
            and self.arch in SUPPORTED_ARCHES
        )


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
    return classify_family(os_release) == "debian"


def classify_family(os_release: Mapping[str, str]) -> str:
    distro_id = os_release.get("ID", "").lower()
    like = os_release.get("ID_LIKE", "").lower().split()
    if distro_id in DEBIAN_IDS or "debian" in like or "ubuntu" in like:
        return "debian"
    if distro_id in RHEL_IDS or any(
        token in like for token in ("fedora", "rhel", "centos")
    ):
        return "rhel"
    if distro_id in SUSE_IDS or any(
        token in like for token in ("suse", "opensuse")
    ):
        return "suse"
    raise UnsupportedPlatformError(
        f"unsupported OS family: {os_release.get('ID', 'unknown')}"
    )


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


def probe_package_managers(
    *,
    which: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    found: list[str] = []
    for binary, name in _MANAGER_BINARIES:
        if which is not None:
            present = binary in which or name in which
        else:
            present = shutil.which(binary) is not None
        if present and name not in found:
            found.append(name)
    return tuple(found)


def select_package_manager(
    family: str,
    available: tuple[str, ...] | None = None,
) -> str:
    preferred = _FAMILY_MANAGERS.get(family, ())
    candidates = available if available is not None else preferred
    for name in preferred:
        if name in candidates:
            return name
    for name in candidates:
        if name in SUPPORTED_PACKAGE_MANAGERS:
            return name
    raise UnsupportedPlatformError(
        f"no supported package manager for {family} "
        f"(need apt, dnf, yum, or zypper)"
    )


def detect_platform(
    *,
    os_release_text: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    machine: str | None = None,
    model_text: str = "",
    device_tree_path: Path = Path("/proc/device-tree/model"),
    available_package_managers: tuple[str, ...] | None = None,
) -> Platform:
    live = os_release_text is None
    if os_release_text is None:
        if not os_release_path.is_file():
            raise UnsupportedPlatformError("missing /etc/os-release")
        os_release_text = os_release_path.read_text(encoding="utf-8")
    os_release = parse_os_release(os_release_text)
    family = classify_family(os_release)
    resolved_machine = machine if machine is not None else platform.machine()
    arch = normalize_arch(resolved_machine)
    if arch not in SUPPORTED_ARCHES:
        raise UnsupportedPlatformError(f"unsupported architecture: {arch}")
    if available_package_managers is None and live:
        available_package_managers = probe_package_managers()
    package_manager = select_package_manager(family, available_package_managers)
    tree_model = ""
    if not model_text and device_tree_path.is_file():
        tree_model = device_tree_path.read_text(encoding="utf-8", errors="replace")
    return Platform(
        family=family,
        package_manager=package_manager,
        distro_id=os_release.get("ID", family).lower(),
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
