"""Configure dumpcap capabilities without granting them to the backend."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from appliance.host import Host
from appliance.paths import DUMPCAP_CAPS, DUMPCAP_MODE, WIRESHARK_GROUP


FORBIDDEN_BACKEND_CAP_NAMES = ("cap_net_raw", "cap_net_admin")


@dataclass(frozen=True)
class DumpcapReport:
    path: Path
    owner: str
    group: str
    mode: int
    capabilities: str
    setuid: bool
    service_user: str
    service_in_wireshark: bool
    python_capabilities: tuple[str, ...]
    ok: bool
    issues: tuple[str, ...]


def _cap_list(raw: str) -> tuple[str, ...]:
    cleaned = raw.replace("=", " ").replace(",", " ").replace("+", " ")
    return tuple(
        item.strip().lower()
        for item in cleaned.split()
        if item.strip().lower().startswith("cap_")
    )


def python_capability_targets(host: Host, venv_python: Path | None = None) -> tuple[Path, ...]:
    targets: list[Path] = []
    for name in ("python3", "python"):
        located = host.which(name)
        if located:
            targets.append(Path(located))
    if venv_python is not None:
        targets.append(venv_python)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in targets:
        key = str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return tuple(unique)


def inspect_dumpcap(
    host: Host,
    *,
    dumpcap_path: Path,
    service_user: str,
    venv_python: Path | None = None,
) -> DumpcapReport:
    issues: list[str] = []
    if not host.is_file(dumpcap_path):
        return DumpcapReport(
            path=dumpcap_path,
            owner="",
            group="",
            mode=0,
            capabilities="",
            setuid=False,
            service_user=service_user,
            service_in_wireshark=False,
            python_capabilities=(),
            ok=False,
            issues=("dumpcap_missing",),
        )
    owner = host.file_owner(dumpcap_path)
    group = host.file_group(dumpcap_path)
    mode = host.file_mode(dumpcap_path)
    setuid = host.has_setuid(dumpcap_path)
    capabilities = host.getcap(dumpcap_path)
    in_group = host.user_in_group(service_user, WIRESHARK_GROUP)
    python_caps: list[str] = []
    for interpreter in python_capability_targets(host, venv_python):
        if host.exists(interpreter):
            python_caps.append(f"{interpreter}={host.getcap(interpreter)}")
    if owner != "root":
        issues.append("dumpcap_owner")
    if group != WIRESHARK_GROUP:
        issues.append("dumpcap_group")
    if mode != DUMPCAP_MODE:
        issues.append("dumpcap_mode")
    if setuid:
        issues.append("dumpcap_setuid")
    cap_names = set(_cap_list(capabilities))
    if "cap_net_raw" not in cap_names or "cap_net_admin" not in cap_names:
        issues.append("dumpcap_capabilities")
    if not in_group:
        issues.append("service_not_in_wireshark")
    for item in python_caps:
        names = set(_cap_list(item.split("=", 1)[-1]))
        if names.intersection(FORBIDDEN_BACKEND_CAP_NAMES):
            issues.append("backend_capabilities")
            break
    return DumpcapReport(
        path=dumpcap_path,
        owner=owner,
        group=group,
        mode=mode,
        capabilities=capabilities,
        setuid=setuid,
        service_user=service_user,
        service_in_wireshark=in_group,
        python_capabilities=tuple(python_caps),
        ok=not issues,
        issues=tuple(issues),
    )


def configure_dumpcap(
    host: Host,
    *,
    dumpcap_path: Path,
    service_user: str,
    venv_python: Path | None = None,
) -> DumpcapReport:
    if not host.is_file(dumpcap_path):
        raise FileNotFoundError(f"dumpcap not found: {dumpcap_path}")
    host.ensure_group(WIRESHARK_GROUP)
    host.add_user_to_group(service_user, WIRESHARK_GROUP)
    if host.has_setuid(dumpcap_path):
        host.chmod(dumpcap_path, DUMPCAP_MODE)
    host.chown(dumpcap_path, "root", WIRESHARK_GROUP)
    host.chmod(dumpcap_path, DUMPCAP_MODE)
    host.setcap(dumpcap_path, DUMPCAP_CAPS)
    report = inspect_dumpcap(
        host,
        dumpcap_path=dumpcap_path,
        service_user=service_user,
        venv_python=venv_python,
    )
    if not report.ok:
        raise RuntimeError(
            "dumpcap least-privilege configuration failed: "
            + ", ".join(report.issues)
        )
    return report
