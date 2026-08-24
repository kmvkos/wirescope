"""Privileged NIC helper. argv arrays only; never shell=True.

Installed to /usr/lib/wirescope/netctl and invoked via a tight sudoers
drop-in. The FastAPI process stays unprivileged.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping


IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,15}$")
ROLES = ("management", "capture")
METHODS = ("dhcp", "static", "none")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
PUBLIC_BIND_HOSTS = frozenset({"0.0.0.0", "::", "*"})
NMCLI_METRIC_CAPTURE = "4096"
HELPER_PATH = Path("/usr/lib/wirescope/netctl")
SUDOERS_PATH = Path("/etc/sudoers.d/wirescope-netctl")
ROLES_PATH = Path("/etc/wirescope/network-roles.json")
INTERFACES_PATH = Path("/etc/network/interfaces")
INTERFACES_D = Path("/etc/network/interfaces.d")
NETWORKD_DIR = Path("/etc/systemd/network")

WhichFn = Callable[[str], str | None]


class NetctlError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass(frozen=True)
class CmdResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class NicSnapshot:
    name: str
    mac: str | None
    state: str | None
    ipv4: list[str]
    ipv6: list[str]
    addressing: str
    has_default_route: bool
    role: str
    role_source: str
    is_loopback: bool


@dataclass
class Inventory:
    interfaces: list[NicSnapshot]
    backend: str
    default_route_dev: str | None
    dns: list[str]


@dataclass
class ApplySpec:
    interface: str
    role: str
    method: str
    address: str | None = None
    gateway: str | None = None
    dns: tuple[str, ...] = ()
    confirm: bool = False
    session_interface: str | None = None
    bind_host: str = "0.0.0.0"


@dataclass
class SafetyDecision:
    ok: bool
    needs_confirm: bool
    reasons: list[str] = field(default_factory=list)
    remaining_ipv4: list[str] = field(default_factory=list)


@dataclass
class ApplyResult:
    inventory: Inventory
    gui_urls: list[str]
    warnings: list[str] = field(default_factory=list)


def run_argv(
    argv: list[str],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
) -> CmdResult:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise NetctlError("invalid_argv", "refusing invalid command")
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=dict(os.environ, **env) if env else None,
        )
    except FileNotFoundError:
        return CmdResult(tuple(argv), 127, "", f"not found: {argv[0]}")
    except subprocess.TimeoutExpired as exc:
        raise NetctlError("timeout", f"command timed out: {argv[0]}") from exc
    return CmdResult(
        tuple(argv),
        completed.returncode,
        completed.stdout or "",
        completed.stderr or "",
    )


def validate_interface_name(name: str) -> str:
    if not IFACE_RE.fullmatch(name or ""):
        raise NetctlError("invalid_interface", f"Invalid interface name: {name}")
    return name


def validate_spec(spec: ApplySpec) -> ApplySpec:
    validate_interface_name(spec.interface)
    if spec.role not in ROLES:
        raise NetctlError("invalid_role", f"Role must be management or capture")
    if spec.method not in METHODS:
        raise NetctlError("invalid_method", f"Method must be dhcp, static, or none")
    if spec.role == "management" and spec.method == "none":
        raise NetctlError(
            "management_needs_address",
            "Management interface must use DHCP or a static IPv4 address",
        )
    if spec.method == "static":
        if not spec.address:
            raise NetctlError("address_required", "Static addressing needs address/prefix")
        try:
            iface = ipaddress.ip_interface(spec.address)
        except ValueError as exc:
            raise NetctlError("invalid_address", f"Invalid address: {spec.address}") from exc
        if iface.version != 4:
            raise NetctlError("ipv4_only", "Only IPv4 static configuration is supported")
        if spec.gateway:
            try:
                gateway = ipaddress.ip_address(spec.gateway)
            except ValueError as exc:
                raise NetctlError("invalid_gateway", f"Invalid gateway: {spec.gateway}") from exc
            if gateway.version != 4:
                raise NetctlError("ipv4_only", "Gateway must be IPv4")
    elif spec.address:
        raise NetctlError("address_not_allowed", "Address is only used with static method")
    dns: list[str] = []
    for item in spec.dns:
        try:
            parsed = ipaddress.ip_address(item)
        except ValueError as exc:
            raise NetctlError("invalid_dns", f"Invalid DNS server: {item}") from exc
        if parsed.version != 4:
            raise NetctlError("ipv4_only", "DNS servers must be IPv4")
        dns.append(str(parsed))
    spec.dns = tuple(dns)
    return spec


def lan_bound(bind_host: str) -> bool:
    host = (bind_host or "").strip()
    return host not in LOOPBACK_HOSTS and host != ""


def gui_urls(
    *,
    bind_host: str,
    bind_port: int,
    interfaces: list[NicSnapshot],
    tls: bool = False,
) -> list[str]:
    scheme = "https" if tls else "http"
    port = bind_port
    if not lan_bound(bind_host):
        return [f"{scheme}://127.0.0.1:{port}/"]
    urls: list[str] = []
    if bind_host not in PUBLIC_BIND_HOSTS:
        urls.append(f"{scheme}://{bind_host}:{port}/")
    urls.append(f"{scheme}://127.0.0.1:{port}/")
    for nic in interfaces:
        if nic.is_loopback:
            continue
        if str(nic.state or "").upper() not in {"UP", "UNKNOWN"}:
            continue
        for value in nic.ipv4:
            address = value.split("/", 1)[0]
            if address in LOOPBACK_HOSTS:
                continue
            urls.append(f"{scheme}://{address}:{port}/")
    return list(dict.fromkeys(urls))


def load_roles(path: Path = ROLES_PATH) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    result: dict[str, str] = {}
    for name, role in payload.items():
        if IFACE_RE.fullmatch(str(name)) and role in ROLES:
            result[str(name)] = str(role)
    return result


def save_roles(roles: dict[str, str], path: Path = ROLES_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(roles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o640)


def _json_command(runner, argv: list[str]) -> list | dict | None:
    result = runner(argv)
    if not result.ok or not result.stdout.strip():
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return payload


def _dns_servers() -> list[str]:
    servers: list[str] = []
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
    except OSError:
        return servers
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) >= 2:
                servers.append(parts[1])
    return servers


def _addressing_from_addr_info(addr_info: list) -> str:
    has_v4 = False
    dhcp = False
    for item in addr_info:
        if item.get("family") != "inet":
            continue
        has_v4 = True
        if item.get("dynamic") is True:
            dhcp = True
    if not has_v4:
        return "none"
    return "dhcp" if dhcp else "static"


def infer_role(
    nic: NicSnapshot,
    *,
    configured: Mapping[str, str],
    default_dev: str | None,
    non_loopback: int,
) -> tuple[str, str]:
    if nic.name in configured:
        return configured[nic.name], "configured"
    if nic.is_loopback:
        return "unknown", "inferred"
    if default_dev and nic.name == default_dev:
        return "management", "inferred"
    if nic.ipv4 and nic.has_default_route:
        return "management", "inferred"
    if not nic.ipv4:
        return "capture", "inferred"
    if non_loopback == 1:
        return "management", "inferred"
    return "unknown", "inferred"


def collect_inventory(
    runner: Callable[[list[str]], CmdResult] = run_argv,
    *,
    which: WhichFn = shutil.which,
    roles_path: Path = ROLES_PATH,
    backend: str | None = None,
) -> Inventory:
    addr_payload = _json_command(runner, ["ip", "-j", "addr"]) or []
    route_payload = _json_command(runner, ["ip", "-j", "route"]) or []
    if not isinstance(addr_payload, list):
        raise NetctlError("discovery_failed", "iproute2 address JSON must be a list")
    if isinstance(route_payload, list) and route_payload and "ifname" in route_payload[0]:
        route_payload = []
    if not isinstance(route_payload, list):
        route_payload = []
    default_devs = {
        str(item.get("dev") or "")
        for item in route_payload
        if isinstance(item, dict)
        and item.get("dst") in {None, "", "default", "unspecified", "0.0.0.0/0"}
    }
    default_devs.discard("")
    default_dev = next(iter(default_devs), None)
    configured = load_roles(roles_path)
    nics: list[NicSnapshot] = []
    for item in addr_payload:
        if not isinstance(item, dict) or not item.get("ifname"):
            continue
        name = str(item["ifname"])
        flags = {str(flag).upper() for flag in item.get("flags", [])}
        is_loopback = (
            name == "lo"
            or "LOOPBACK" in flags
            or item.get("link_type") == "loopback"
        )
        ipv4: list[str] = []
        ipv6: list[str] = []
        for address in item.get("addr_info") or []:
            local = address.get("local")
            prefix = address.get("prefixlen")
            if local is None or prefix is None:
                continue
            value = f"{local}/{prefix}"
            if address.get("family") == "inet":
                ipv4.append(value)
            elif address.get("family") == "inet6":
                ipv6.append(value)
        nics.append(
            NicSnapshot(
                name=name,
                mac=item.get("address"),
                state=item.get("operstate"),
                ipv4=ipv4,
                ipv6=ipv6,
                addressing=_addressing_from_addr_info(item.get("addr_info") or []),
                has_default_route=name in default_devs,
                role="unknown",
                role_source="inferred",
                is_loopback=is_loopback,
            )
        )
    non_loopback = sum(1 for nic in nics if not nic.is_loopback)
    for nic in nics:
        role, source = infer_role(
            nic,
            configured=configured,
            default_dev=default_dev,
            non_loopback=non_loopback,
        )
        nic.role = role
        nic.role_source = source
    return Inventory(
        interfaces=nics,
        backend=backend or detect_backend(runner, which=which),
        default_route_dev=default_dev,
        dns=_dns_servers(),
    )


def detect_backend(
    runner: Callable[[list[str]], CmdResult] = run_argv,
    *,
    which: WhichFn = shutil.which,
) -> str:
    nmcli = which("nmcli")
    if nmcli:
        status = runner([nmcli, "-t", "-f", "RUNNING", "general", "status"])
        if status.ok and "running" in status.stdout.lower():
            return "nmcli"
    if INTERFACES_PATH.is_file() or which("ifup"):
        return "ifupdown"
    if NETWORKD_DIR.is_dir() or which("networkctl"):
        return "networkd"
    return "ip"


def ipv4_hosts(interfaces: list[NicSnapshot]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for nic in interfaces:
        if nic.is_loopback:
            continue
        for value in nic.ipv4:
            found.append((nic.name, value.split("/", 1)[0]))
    return found


def projected_ipv4(inventory: Inventory, spec: ApplySpec) -> list[tuple[str, str]]:
    remaining: list[tuple[str, str]] = []
    for name, address in ipv4_hosts(inventory.interfaces):
        if name == spec.interface:
            continue
        remaining.append((name, address))
    if spec.method == "static" and spec.address:
        remaining.append((spec.interface, spec.address.split("/", 1)[0]))
    elif spec.method == "dhcp":
        remaining.append((spec.interface, "dhcp"))
    return remaining


def evaluate_safety(inventory: Inventory, spec: ApplySpec) -> SafetyDecision:
    reasons: list[str] = []
    projected = projected_ipv4(inventory, spec)
    real_ipv4 = [item for item in projected if item[1] != "dhcp"]
    dhcp_kept = any(item[1] == "dhcp" for item in projected)
    if lan_bound(spec.bind_host) and not real_ipv4 and not dhcp_kept:
        reasons.append("last_lan_ipv4")
    if (
        spec.session_interface
        and spec.session_interface == spec.interface
        and spec.session_interface not in LOOPBACK_HOSTS
        and spec.session_interface != "lo"
        and spec.method == "none"
    ):
        reasons.append("session_iface")
    if (
        spec.session_interface
        and spec.session_interface == spec.interface
        and spec.role == "capture"
        and spec.method != "dhcp"
        and spec.method != "static"
    ):
        if "session_iface" not in reasons:
            reasons.append("session_iface")
    remaining = [f"{name}:{address}" for name, address in projected]
    needs = bool(reasons)
    return SafetyDecision(
        ok=not needs or spec.confirm,
        needs_confirm=needs and not spec.confirm,
        reasons=reasons,
        remaining_ipv4=remaining,
    )


def session_interface_for(
    client_host: str | None,
    runner: Callable[[list[str]], CmdResult] = run_argv,
) -> str | None:
    host = (client_host or "").strip()
    if not host or host in LOOPBACK_HOSTS or host in {"testclient", "testserver"}:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    payload = _json_command(runner, ["ip", "-j", "route", "get", host])
    if not isinstance(payload, list) or not payload:
        return None
    first = payload[0]
    if not isinstance(first, dict):
        return None
    dev = str(first.get("dev") or "")
    return dev or None


def nic_to_dict(nic: NicSnapshot) -> dict[str, object]:
    return {
        "name": nic.name,
        "mac": nic.mac,
        "state": nic.state,
        "ipv4": list(nic.ipv4),
        "ipv6": list(nic.ipv6),
        "addressing": nic.addressing,
        "has_default_route": nic.has_default_route,
        "role": nic.role,
        "role_source": nic.role_source,
        "is_loopback": nic.is_loopback,
    }


def inventory_to_dict(inventory: Inventory) -> dict[str, object]:
    return {
        "interfaces": [nic_to_dict(item) for item in inventory.interfaces],
        "backend": inventory.backend,
        "default_route_dev": inventory.default_route_dev,
        "dns": list(inventory.dns),
    }


def _require_ok(result: CmdResult, code: str, message: str) -> None:
    if result.ok:
        return
    detail = (result.stderr or result.stdout).strip()
    raise NetctlError(
        code,
        message + (f": {detail}" if detail else ""),
        details={"argv": list(result.argv), "returncode": result.returncode},
    )


def _nmcli_connection(
    runner: Callable[[list[str]], CmdResult],
    nmcli: str,
    iface: str,
) -> str:
    listed = runner([nmcli, "-t", "-f", "NAME,DEVICE", "connection", "show"])
    if listed.ok:
        for line in listed.stdout.splitlines():
            name, _, device = line.partition(":")
            if device == iface and name:
                return name
    desired = f"wirescope-{iface}"
    added = runner(
        [
            nmcli,
            "connection",
            "add",
            "type",
            "ethernet",
            "ifname",
            iface,
            "con-name",
            desired,
        ]
    )
    if added.ok or "already exists" in (added.stderr + added.stdout).lower():
        return desired
    _require_ok(added, "nmcli_failed", "nmcli connection add failed")
    return desired


def apply_nmcli(
    spec: ApplySpec,
    runner: Callable[[list[str]], CmdResult],
    *,
    which: WhichFn,
) -> list[str]:
    nmcli = which("nmcli")
    if not nmcli:
        raise NetctlError("nmcli_missing", "nmcli is not installed")
    warnings: list[str] = []
    con = _nmcli_connection(runner, nmcli, spec.interface)
    modify = [nmcli, "connection", "modify", con]
    if spec.method == "dhcp":
        modify.extend(["ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", ""])
    elif spec.method == "static":
        modify.extend(
            [
                "ipv4.method",
                "manual",
                "ipv4.addresses",
                spec.address or "",
            ]
        )
        if spec.gateway:
            modify.extend(["ipv4.gateway", spec.gateway])
        else:
            modify.extend(["ipv4.gateway", ""])
    else:
        modify.extend(["ipv4.method", "disabled", "ipv4.addresses", "", "ipv4.gateway", ""])
    if spec.dns:
        modify.extend(["ipv4.dns", " ".join(spec.dns)])
    else:
        modify.extend(["ipv4.dns", ""])
    if spec.role == "capture":
        modify.extend(
            [
                "ipv4.never-default",
                "yes",
                "ipv6.never-default",
                "yes",
                "ipv4.route-metric",
                NMCLI_METRIC_CAPTURE,
            ]
        )
    else:
        modify.extend(["ipv4.never-default", "no", "ipv6.never-default", "no"])
    modify.extend(["connection.autoconnect", "yes", "ipv6.method", "ignore"])
    _require_ok(runner(modify), "nmcli_failed", "nmcli connection modify failed")
    _require_ok(
        runner([nmcli, "connection", "up", con]),
        "nmcli_failed",
        "nmcli connection up failed",
    )
    if spec.role == "capture":
        _drop_default_via(runner, spec.interface)
        warnings.append("capture_no_default_route")
    return warnings


def _drop_default_via(
    runner: Callable[[list[str]], CmdResult],
    iface: str,
) -> None:
    listed = _json_command(runner, ["ip", "-j", "route", "show", "default"]) or []
    if not isinstance(listed, list):
        return
    for item in listed:
        if not isinstance(item, dict) or item.get("dev") != iface:
            continue
        argv = ["ip", "route", "del", "default", "dev", iface]
        gateway = item.get("gateway")
        if gateway:
            argv.extend(["via", str(gateway)])
        runner(argv)


def _iface_stanza(spec: ApplySpec) -> str:
    lines = [f"auto {spec.interface}"]
    if spec.method == "dhcp":
        lines.append(f"iface {spec.interface} inet dhcp")
        if spec.role == "capture":
            lines.append(f"    metric {NMCLI_METRIC_CAPTURE}")
    elif spec.method == "static":
        lines.append(f"iface {spec.interface} inet static")
        lines.append(f"    address {spec.address}")
        if spec.gateway and spec.role == "management":
            lines.append(f"    gateway {spec.gateway}")
        if spec.dns:
            lines.append("    dns-nameservers " + " ".join(spec.dns))
    else:
        lines.append(f"iface {spec.interface} inet manual")
        lines.append("    pre-up /sbin/ip link set $IFACE up")
    lines.append("")
    return "\n".join(lines)


def _strip_iface_stanzas(text: str, iface: str) -> str:
    keep: list[str] = []
    skipping = False
    marker = f"# WireScope manages {iface} in {INTERFACES_D / f'wirescope-{iface}'}"
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped == marker:
            continue
        tokens = stripped.split()
        if tokens and tokens[0] in {"auto", "allow-hotplug", "iface"} and iface in tokens:
            skipping = True
            continue
        if skipping:
            if stripped and not line[:1].isspace() and tokens and tokens[0] not in {"#"}:
                skipping = False
            else:
                continue
        keep.append(line)
    rebuilt = "".join(keep).rstrip() + "\n"
    if marker not in rebuilt:
        rebuilt += f"{marker}\n"
    return rebuilt


def apply_ifupdown(
    spec: ApplySpec,
    runner: Callable[[list[str]], CmdResult],
    *,
    which: WhichFn,
    interfaces_path: Path = INTERFACES_PATH,
    interfaces_d: Path = INTERFACES_D,
) -> list[str]:
    warnings: list[str] = []
    snippet = interfaces_d / f"wirescope-{spec.interface}"
    interfaces_d.mkdir(parents=True, exist_ok=True)
    if interfaces_path.is_file():
        original = interfaces_path.read_text(encoding="utf-8")
        interfaces_path.write_text(
            _strip_iface_stanzas(original, spec.interface),
            encoding="utf-8",
        )
    snippet.write_text(_iface_stanza(spec), encoding="utf-8")
    os.chmod(snippet, 0o644)
    ifdown = which("ifdown") or "/sbin/ifdown"
    ifup = which("ifup") or "/sbin/ifup"
    runner([ifdown, "--force", spec.interface])
    up = runner([ifup, spec.interface])
    if not up.ok:
        warnings.extend(_apply_ip_live(spec, runner))
        warnings.append("ifup_fallback_ip")
    if spec.role == "capture":
        _drop_default_via(runner, spec.interface)
        warnings.append("capture_no_default_route")
        if spec.method == "none":
            runner(["ip", "addr", "flush", "dev", spec.interface])
            runner(["ip", "link", "set", spec.interface, "up"])
    return warnings


def apply_networkd(
    spec: ApplySpec,
    runner: Callable[[list[str]], CmdResult],
    *,
    which: WhichFn,
    networkd_dir: Path = NETWORKD_DIR,
) -> list[str]:
    warnings: list[str] = []
    networkd_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# WireScope-managed {spec.interface}",
        "[Match]",
        f"Name={spec.interface}",
        "",
        "[Network]",
    ]
    if spec.method == "dhcp":
        lines.append("DHCP=ipv4")
        if spec.role == "capture":
            lines.append("IPv4DefaultRoute=no")
    elif spec.method == "static":
        lines.append("DHCP=no")
        lines.append(f"Address={spec.address}")
        if spec.gateway and spec.role == "management":
            lines.append(f"Gateway={spec.gateway}")
        for server in spec.dns:
            lines.append(f"DNS={server}")
    else:
        lines.extend(["DHCP=no", "LinkLocalAddressing=no"])
    lines.extend(["", "[Link]", "RequiredForOnline=no", ""])
    path = networkd_dir / f"20-wirescope-{spec.interface}.network"
    path.write_text("\n".join(lines), encoding="utf-8")
    networkctl = which("networkctl") or "/usr/bin/networkctl"
    runner([networkctl, "reload"])
    runner([networkctl, "reconfigure", spec.interface])
    if spec.role == "capture":
        _drop_default_via(runner, spec.interface)
        warnings.append("capture_no_default_route")
        if spec.method == "none":
            runner(["ip", "addr", "flush", "dev", spec.interface])
            runner(["ip", "link", "set", spec.interface, "up"])
    return warnings


def _apply_ip_live(
    spec: ApplySpec,
    runner: Callable[[list[str]], CmdResult],
) -> list[str]:
    warnings = ["not_persistent"]
    runner(["ip", "link", "set", spec.interface, "up"])
    runner(["ip", "addr", "flush", "dev", spec.interface])
    if spec.method == "static" and spec.address:
        _require_ok(
            runner(["ip", "addr", "add", spec.address, "dev", spec.interface]),
            "ip_failed",
            "ip addr add failed",
        )
        if spec.gateway and spec.role == "management":
            runner(
                [
                    "ip",
                    "route",
                    "replace",
                    "default",
                    "via",
                    spec.gateway,
                    "dev",
                    spec.interface,
                ]
            )
    elif spec.method == "dhcp":
        dhclient = shutil.which("dhclient") or shutil.which("dhcpcd")
        if not dhclient:
            raise NetctlError("dhcp_client_missing", "No dhclient/dhcpcd for live DHCP")
        argv = [dhclient]
        if Path(dhclient).name == "dhclient":
            argv.extend(["-1", spec.interface])
        else:
            argv.extend(["-n", spec.interface])
        _require_ok(runner(argv), "dhcp_failed", "DHCP client failed")
    if spec.role == "capture":
        _drop_default_via(runner, spec.interface)
    return warnings


def apply_configuration(
    spec: ApplySpec,
    runner: Callable[[list[str]], CmdResult] = run_argv,
    *,
    which: WhichFn = shutil.which,
    roles_path: Path = ROLES_PATH,
    bind_port: int = 8000,
    tls: bool = False,
) -> ApplyResult:
    spec = validate_spec(spec)
    inventory = collect_inventory(runner, which=which, roles_path=roles_path)
    names = {item.name for item in inventory.interfaces}
    if spec.interface not in names:
        raise NetctlError("unknown_interface", f"Unknown network interface: {spec.interface}")
    safety = evaluate_safety(inventory, spec)
    if safety.needs_confirm:
        raise NetctlError(
            "confirm_required",
            "This change needs confirmation: it may remove the last LAN IPv4 "
            "or the interface serving this GUI session",
            details={"reasons": safety.reasons, "remaining_ipv4": safety.remaining_ipv4},
        )
    if not safety.ok:
        raise NetctlError("unsafe", "Refusing unsafe network change")
    backend = inventory.backend
    warnings: list[str] = []
    if backend == "nmcli":
        warnings.extend(apply_nmcli(spec, runner, which=which))
    elif backend == "ifupdown":
        warnings.extend(apply_ifupdown(spec, runner, which=which))
    elif backend == "networkd":
        warnings.extend(apply_networkd(spec, runner, which=which))
    else:
        warnings.extend(_apply_ip_live(spec, runner))
    roles = load_roles(roles_path)
    roles[spec.interface] = spec.role
    save_roles(roles, roles_path)
    updated = collect_inventory(runner, which=which, roles_path=roles_path)
    return ApplyResult(
        inventory=updated,
        gui_urls=gui_urls(
            bind_host=spec.bind_host,
            bind_port=bind_port,
            interfaces=updated.interfaces,
            tls=tls,
        ),
        warnings=warnings,
    )


def sudoers_text(helper: Path = HELPER_PATH, user: str = "wirescope") -> str:
    return (
        "# WireScope: unprivileged API may run only this helper as root.\n"
        f"{user} ALL=(root) NOPASSWD: {helper}\n"
    )


def helper_script_text(source: Path | None = None) -> str:
    path = source or Path(__file__)
    body = path.read_text(encoding="utf-8")
    if body.startswith("#!"):
        return body
    return "#!/usr/bin/python3\n" + body


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wirescope-netctl")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Print JSON inventory")
    apply_cmd = sub.add_parser("apply", help="Apply DHCP/static/none and a role")
    apply_cmd.add_argument("--interface", required=True)
    apply_cmd.add_argument("--role", required=True, choices=ROLES)
    apply_cmd.add_argument("--method", required=True, choices=METHODS)
    apply_cmd.add_argument("--address", default="")
    apply_cmd.add_argument("--gateway", default="")
    apply_cmd.add_argument("--dns", action="append", default=[])
    apply_cmd.add_argument("--confirm", action="store_true")
    apply_cmd.add_argument("--session-interface", default="")
    apply_cmd.add_argument("--bind-host", default=os.getenv("WIRESCOPE_BIND_HOST", "0.0.0.0"))
    apply_cmd.add_argument("--bind-port", type=int, default=int(os.getenv("WIRESCOPE_BIND_PORT", "8000")))
    return parser


def _print_json(payload: dict) -> int:
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            inventory = collect_inventory()
            return _print_json(inventory_to_dict(inventory))
        spec = ApplySpec(
            interface=args.interface,
            role=args.role,
            method=args.method,
            address=args.address or None,
            gateway=args.gateway or None,
            dns=tuple(args.dns),
            confirm=args.confirm,
            session_interface=args.session_interface or None,
            bind_host=args.bind_host,
        )
        result = apply_configuration(spec, bind_port=args.bind_port)
        return _print_json(
            {
                **inventory_to_dict(result.inventory),
                "gui_urls": result.gui_urls,
                "warnings": result.warnings,
            }
        )
    except NetctlError as exc:
        json.dump(
            {"error": exc.code, "message": exc.message, "details": exc.details},
            sys.stderr,
        )
        sys.stderr.write("\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
