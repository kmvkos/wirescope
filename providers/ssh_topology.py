"""Read-only topology collection through a tightly bounded SSH command set.

The operator cannot provide a remote command.  WireScope invokes only the fixed
commands below, validates target/user/port separately, requires host-key
verification and never uses a local shell.  Unsupported commands are recorded
as unavailable capabilities instead of failing the whole enrichment job.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from config.settings import Settings
from providers.tools import CancellationToken, ToolCommand, ToolRunner


_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 12


class SshTopologyCredentialError(ValueError):
    pass


def sanitize_ssh_profile(credentials: dict[str, Any]) -> dict[str, Any]:
    username = str(credentials.get("username") or "").strip()
    if not _USERNAME_RE.fullmatch(username):
        raise SshTopologyCredentialError("SSH username contains unsupported characters")
    try:
        port = int(credentials.get("port") or 22)
    except (TypeError, ValueError) as exc:
        raise SshTopologyCredentialError("SSH port is invalid") from exc
    if port < 1 or port > 65535:
        raise SshTopologyCredentialError("SSH port must be between 1 and 65535")
    authentication = str(credentials.get("authentication") or "private_key")
    if authentication not in {"private_key", "agent"}:
        raise SshTopologyCredentialError("Unsupported SSH authentication mode")
    if authentication == "private_key" and not str(credentials.get("private_key") or "").strip():
        raise SshTopologyCredentialError("SSH private key is required")
    if not str(credentials.get("known_hosts") or "").strip():
        raise SshTopologyCredentialError("SSH known_hosts entry is required for host-key verification")
    return {
        "username": username,
        "port": port,
        "authentication": authentication,
        "host_key_verification": "strict",
    }


class SshTopologyProvider:
    def __init__(self, *, settings: Settings, runner: ToolRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or ToolRunner()

    def collect(
        self,
        *,
        target: str,
        credentials: dict[str, Any],
        identity_file: Path | None,
        known_hosts_file: Path,
        interface: str,
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        target_ip = str(ipaddress.ip_address(target))
        profile = sanitize_ssh_profile(credentials)
        if shutil.which("ssh") is None:
            return {
                "schema": "ssh-topology-result",
                "schema_version": 1,
                "status": "tool_unavailable",
                "target": target_ip,
                "interface": interface,
                "credential_profile": profile,
                "interfaces": [],
                "routes": [],
                "neighbors": [],
                "fdb": [],
                "vlans": [],
                "wifi_associations": [],
                "capabilities": {},
                "warnings": ["OpenSSH client is not installed; SSH topology enrichment was skipped."],
            }

        collections: dict[str, Any] = {}
        capabilities: dict[str, bool] = {}
        warnings: list[str] = []
        commands = [
            ("interfaces", ["ip", "-j", "addr", "show"]),
            ("routes", ["ip", "-j", "route", "show", "table", "main"]),
            ("neighbors", ["ip", "-j", "neigh", "show"]),
            ("fdb", ["bridge", "-j", "fdb", "show"]),
            ("vlans", ["bridge", "-j", "vlan", "show"]),
            ("wifi_devices", ["iw", "dev"]),
        ]
        for index, (name, remote_args) in enumerate(commands, start=1):
            if cancellation_token is not None and cancellation_token.cancelled:
                break
            if progress:
                progress(5 + int(index * 60 / len(commands)), f"SSH read-only: {name}")
            result = self._run(
                target=target_ip,
                profile=profile,
                identity_file=identity_file,
                known_hosts_file=known_hosts_file,
                remote_args=remote_args,
                cancellation_token=cancellation_token,
            )
            capabilities[name] = bool(result.success)
            if not result.success:
                warnings.append(_command_warning(name, result))
                collections[name] = [] if name != "wifi_devices" else ""
                continue
            if len(result.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
                warnings.append(f"SSH {name} output exceeded the bounded parser limit and was ignored.")
                capabilities[name] = False
                collections[name] = [] if name != "wifi_devices" else ""
                continue
            if name == "wifi_devices":
                collections[name] = result.stdout
            else:
                parsed = _json_rows(result.stdout)
                if parsed is None:
                    capabilities[name] = False
                    warnings.append(f"SSH {name} returned data in an unsupported format.")
                    collections[name] = []
                else:
                    collections[name] = parsed

        wifi_associations: list[dict[str, Any]] = []
        wifi_interfaces = _wifi_interfaces(str(collections.get("wifi_devices") or ""))
        for index, wifi_interface in enumerate(wifi_interfaces[:16], start=1):
            if cancellation_token is not None and cancellation_token.cancelled:
                break
            if progress:
                progress(68 + int(index * 14 / max(1, len(wifi_interfaces[:16]))), f"SSH Wi-Fi clients: {wifi_interface}")
            result = self._run(
                target=target_ip,
                profile=profile,
                identity_file=identity_file,
                known_hosts_file=known_hosts_file,
                remote_args=["iw", "dev", wifi_interface, "station", "dump"],
                cancellation_token=cancellation_token,
            )
            key = f"wifi_station:{wifi_interface}"
            capabilities[key] = bool(result.success)
            if result.success:
                wifi_associations.extend(_parse_station_dump(result.stdout, wifi_interface))
            else:
                warnings.append(_command_warning(key, result))

        interfaces = _normalize_interfaces(collections.get("interfaces") or [])
        routes = _normalize_routes(collections.get("routes") or [])
        neighbors = _normalize_neighbors(collections.get("neighbors") or [])
        fdb = _normalize_fdb(collections.get("fdb") or [])
        vlans = _normalize_vlans(collections.get("vlans") or [])
        any_data = any([interfaces, routes, neighbors, fdb, vlans, wifi_associations])
        return {
            "schema": "ssh-topology-result",
            "schema_version": 1,
            "status": "completed" if any_data else "no_data",
            "target": target_ip,
            "interface": interface,
            "credential_profile": profile,
            "interfaces": interfaces,
            "routes": routes,
            "neighbors": neighbors,
            "fdb": fdb,
            "vlans": vlans,
            "wifi_associations": wifi_associations,
            "capabilities": capabilities,
            "collection": {
                "tool": "ssh",
                "fixed_command_allowlist": True,
                "shell_from_operator_input": False,
                "strict_host_key_checking": True,
                "write_operations": 0,
            },
            "warnings": _unique(warnings),
        }

    def _run(
        self,
        *,
        target: str,
        profile: dict[str, Any],
        identity_file: Path | None,
        known_hosts_file: Path,
        remote_args: list[str],
        cancellation_token: CancellationToken | None,
    ):
        args = [
            "-F", "/dev/null",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts_file}",
            "-o", "LogLevel=ERROR",
        ]
        if profile["authentication"] == "private_key":
            if identity_file is None:
                raise SshTopologyCredentialError("SSH identity file is missing")
            args.extend(["-o", "IdentitiesOnly=yes", "-i", str(identity_file)])
        args.extend([
            "-p", str(profile["port"]),
            f"{profile['username']}@{target}",
            "--",
            *remote_args,
        ])
        return self.runner.run(
            ToolCommand(
                tool="ssh",
                args=args,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                environment={"LC_ALL": "C"},
            ),
            cancellation_token=cancellation_token,
        )


def _json_rows(text: str) -> list[dict[str, Any]] | None:
    try:
        payload = json.loads(text or "[]")
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        return None
    return payload[:8192]


def _normalize_interfaces(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows[:2048]:
        name = str(row.get("ifname") or "")
        if not _INTERFACE_RE.fullmatch(name):
            continue
        addresses = []
        for item in row.get("addr_info") or []:
            local = item.get("local")
            prefix = item.get("prefixlen")
            if local is None or prefix is None:
                continue
            try:
                address = ipaddress.ip_interface(f"{local}/{int(prefix)}")
            except (ValueError, TypeError):
                continue
            addresses.append(str(address))
        result.append({
            "name": name,
            "ifindex": row.get("ifindex"),
            "mac": row.get("address"),
            "mtu": row.get("mtu"),
            "state": row.get("operstate"),
            "addresses": _unique(addresses),
        })
    return result


def _normalize_routes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows[:4096]:
        dev = str(row.get("dev") or "")
        if dev and not _INTERFACE_RE.fullmatch(dev):
            continue
        destination = str(row.get("dst") or "default")
        gateway = row.get("gateway")
        if gateway is not None:
            try:
                gateway = str(ipaddress.ip_address(str(gateway)))
            except ValueError:
                gateway = None
        result.append({
            "destination": destination,
            "gateway": gateway,
            "interface": dev or None,
            "source_address": row.get("prefsrc") or row.get("src"),
            "metric": row.get("metric"),
            "protocol": row.get("protocol"),
        })
    return result


def _normalize_neighbors(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows[:8192]:
        try:
            address = str(ipaddress.ip_address(str(row.get("dst") or "")))
        except ValueError:
            continue
        dev = str(row.get("dev") or "")
        if dev and not _INTERFACE_RE.fullmatch(dev):
            continue
        lladdr = str(row.get("lladdr") or "").lower() or None
        result.append({
            "address": address,
            "mac": lladdr,
            "interface": dev or None,
            "state": row.get("state"),
        })
    return result


def _normalize_fdb(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows[:8192]:
        mac = str(row.get("mac") or row.get("lladdr") or "").lower()
        dev = str(row.get("dev") or "")
        if not mac or (dev and not _INTERFACE_RE.fullmatch(dev)):
            continue
        vlan = row.get("vlan")
        try:
            vlan = int(vlan) if vlan is not None else None
        except (TypeError, ValueError):
            vlan = None
        result.append({
            "mac": mac,
            "port": dev or None,
            "vlan_id": vlan,
            "master": row.get("master"),
            "state": row.get("state"),
            "flags": row.get("flags") or [],
        })
    return result


def _normalize_vlans(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows[:2048]:
        port = str(row.get("ifname") or row.get("dev") or "")
        if not _INTERFACE_RE.fullmatch(port):
            continue
        tagged: list[int] = []
        untagged: list[int] = []
        pvid = None
        for vlan in row.get("vlans") or []:
            raw_id = vlan.get("vlan") or vlan.get("vlan_id")
            try:
                vlan_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            flags = {str(flag).lower() for flag in (vlan.get("flags") or [])}
            if any("untagged" in flag for flag in flags):
                untagged.append(vlan_id)
            else:
                tagged.append(vlan_id)
            if any("pvid" in flag for flag in flags):
                pvid = vlan_id
        result.append({
            "port": port,
            "pvid": pvid,
            "tagged_vlans": sorted(set(tagged)),
            "untagged_vlans": sorted(set(untagged)),
        })
    return result


def _wifi_interfaces(text: str) -> list[str]:
    result = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("Interface "):
            continue
        name = stripped.split(None, 1)[1].strip()
        if _INTERFACE_RE.fullmatch(name) and name not in result:
            result.append(name)
    return result


def _parse_station_dump(text: str, interface: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        match = re.match(r"^Station\s+([0-9a-fA-F:]{17})\s+\(on\s+([^\)]+)\)", line)
        if match:
            if current:
                result.append(current)
            observed_interface = match.group(2).strip()
            if not _INTERFACE_RE.fullmatch(observed_interface):
                observed_interface = interface
            current = {"mac": match.group(1).lower(), "interface": observed_interface}
            continue
        if current is None or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        normalized = key.lower().replace(" ", "_")
        if normalized == "signal":
            match = re.search(r"-?\d+", value)
            if match:
                current["signal_dbm"] = int(match.group(0))
        elif normalized in {"rx_bytes", "tx_bytes", "rx_packets", "tx_packets"}:
            match = re.search(r"\d+", value)
            if match:
                current[normalized] = int(match.group(0))
    if current:
        result.append(current)
    return result[:4096]


def _command_warning(name: str, result: Any) -> str:
    if getattr(result, "timed_out", False):
        return f"SSH {name} timed out or is not permitted by the read-only account."
    return f"SSH {name} is unavailable or not permitted on the target."


def _unique(values: list[Any]) -> list[Any]:
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


__all__ = [
    "SshTopologyCredentialError",
    "SshTopologyProvider",
    "sanitize_ssh_profile",
]
