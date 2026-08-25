"""Bounded, read-only SNMP collection for topology enrichment.

Only a fixed allow-list of standard read-only MIB objects is queried.  The
provider never guesses communities/users, never performs a root-MIB walk and
never writes SNMP objects.  Credentials arrive from the ephemeral spool and
are marked sensitive in ToolRunner metadata.
"""

from __future__ import annotations

from collections.abc import Callable
import ipaddress
import re
import shutil
from typing import Any

from config.settings import Settings
from providers.tools import CancellationToken, ToolCommand, ToolRunner


MAX_ROWS_PER_WALK = 4096
WALK_TIMEOUT_SECONDS = 10

# System scalars.
SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"

# IF-MIB / BRIDGE-MIB.
IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS = ".1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = ".1.3.6.1.2.1.2.2.1.8"
IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = ".1.3.6.1.2.1.31.1.1.1.18"
DOT1D_BASE_PORT_IFINDEX = ".1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_ENTRY = ".1.3.6.1.2.1.17.4.3.1"

# Q-BRIDGE-MIB (RFC 4363).
DOT1Q_FDB_ENTRY = ".1.3.6.1.2.1.17.7.1.2.2.1"
DOT1Q_VLAN_CURRENT_ENTRY = ".1.3.6.1.2.1.17.7.1.4.2.1"
DOT1Q_VLAN_STATIC_ENTRY = ".1.3.6.1.2.1.17.7.1.4.3.1"
DOT1Q_PVID = ".1.3.6.1.2.1.17.7.1.4.5.1.1"

# IEEE 802.1AB LLDP-MIB.
LLDP_LOC_PORT_ENTRY = ".1.0.8802.1.1.2.1.3.7.1"
LLDP_REM_ENTRY = ".1.0.8802.1.1.2.1.4.1.1"

# Legacy IPv4 ARP table; still widely implemented by switches/routers.
IP_NET_TO_MEDIA_PHYS = ".1.3.6.1.2.1.4.22.1.2"


class SnmpCredentialError(ValueError):
    pass


class SnmpTopologyProvider:
    def __init__(
        self,
        *,
        settings: Settings,
        runner: ToolRunner | None = None,
    ) -> None:
        self.settings = settings
        self.runner = runner or ToolRunner()

    def collect(
        self,
        *,
        target: str,
        credentials: dict[str, Any],
        interface: str,
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        target_ip = str(ipaddress.ip_address(target))
        profile = sanitize_credential_profile(credentials)
        warnings: list[str] = []
        collections: dict[str, list[dict[str, Any]]] = {}
        tool = self.settings.snmpbulkwalk_binary
        get_tool = self.settings.snmpget_binary
        if shutil.which(tool) is None or shutil.which(get_tool) is None:
            return {
                "schema": "snmp-topology-result",
                "schema_version": 1,
                "status": "tool_unavailable",
                "target": target_ip,
                "interface": interface,
                "credential_profile": profile,
                "system": {},
                "interfaces": [],
                "fdb": [],
                "arp": [],
                "lldp_neighbors": [],
                "vlans": [],
                "warnings": ["snmpget/snmpbulkwalk is not installed; SNMP topology enrichment was skipped."],
            }

        if progress:
            progress(4, "Проверяем SNMP и читаем system identity")
        system = self._get_system(
            target_ip,
            credentials,
            cancellation_token=cancellation_token,
            warnings=warnings,
        )

        walks = [
            ("if_descr", IF_DESCR),
            ("if_name", IF_NAME),
            ("if_alias", IF_ALIAS),
            ("if_admin", IF_ADMIN_STATUS),
            ("if_oper", IF_OPER_STATUS),
            ("bridge_ports", DOT1D_BASE_PORT_IFINDEX),
            ("dot1d_fdb", DOT1D_FDB_ENTRY),
            ("dot1q_fdb", DOT1Q_FDB_ENTRY),
            ("vlan_current", DOT1Q_VLAN_CURRENT_ENTRY),
            ("vlan_static", DOT1Q_VLAN_STATIC_ENTRY),
            ("pvid", DOT1Q_PVID),
            ("lldp_local", LLDP_LOC_PORT_ENTRY),
            ("lldp_remote", LLDP_REM_ENTRY),
            ("arp", IP_NET_TO_MEDIA_PHYS),
        ]
        total = len(walks)
        for index, (name, oid) in enumerate(walks, start=1):
            if cancellation_token is not None and cancellation_token.cancelled:
                break
            if progress:
                percentage = 8 + int(72 * index / total)
                progress(percentage, f"SNMP read-only: {name}")
            rows, row_warnings = self._walk(
                target_ip,
                credentials,
                oid,
                cancellation_token=cancellation_token,
            )
            collections[name] = rows
            warnings.extend(row_warnings)

        if progress:
            progress(84, "Коррелируем bridge ports, FDB, VLAN и LLDP")
        normalized = normalize_topology_collections(collections)
        status = "completed" if system or any(collections.values()) else "no_data"
        return {
            "schema": "snmp-topology-result",
            "schema_version": 1,
            "status": status,
            "target": target_ip,
            "interface": interface,
            "credential_profile": profile,
            "system": system,
            **normalized,
            "collection": {
                "tool": tool,
                "walks_attempted": total,
                "fixed_oid_allowlist": True,
                "max_rows_per_walk": MAX_ROWS_PER_WALK,
                "write_operations": 0,
            },
            "warnings": _unique(warnings),
        }

    def _get_system(
        self,
        target: str,
        credentials: dict[str, Any],
        *,
        cancellation_token: CancellationToken | None,
        warnings: list[str],
    ) -> dict[str, Any]:
        args, sensitive = _credential_args(credentials)
        args.extend(["-On", "-t", "2", "-r", "0", _target_spec(target), SYS_DESCR, SYS_NAME])
        result = self.runner.run(
            ToolCommand(
                tool=self.settings.snmpget_binary,
                args=args,
                timeout_seconds=8,
                environment={"LC_ALL": "C"},
                sensitive_arg_indexes={index + 1 for index in sensitive},
            ),
            cancellation_token=cancellation_token,
        )
        if not result.success:
            warnings.append(_failure_message("system identity", result))
            return {}
        rows = _parse_output(result.stdout, max_rows=8)
        by_oid = {row["oid"]: row for row in rows}
        return {
            "description": _text_value(by_oid.get(SYS_DESCR)),
            "name": _text_value(by_oid.get(SYS_NAME)),
        }

    def _walk(
        self,
        target: str,
        credentials: dict[str, Any],
        oid: str,
        *,
        cancellation_token: CancellationToken | None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        args, sensitive = _credential_args(credentials)
        args.extend([
            "-On",
            "-t",
            "2",
            "-r",
            "0",
            "-Cr25",
            _target_spec(target),
            oid,
        ])
        result = self.runner.run(
            ToolCommand(
                tool=self.settings.snmpbulkwalk_binary,
                args=args,
                timeout_seconds=WALK_TIMEOUT_SECONDS,
                environment={"LC_ALL": "C"},
                sensitive_arg_indexes={index + 1 for index in sensitive},
            ),
            cancellation_token=cancellation_token,
        )
        if not result.success:
            return [], [_failure_message(oid, result)]
        rows = _parse_output(result.stdout, max_rows=MAX_ROWS_PER_WALK)
        warnings: list[str] = []
        if len(result.stdout.splitlines()) > MAX_ROWS_PER_WALK:
            warnings.append(f"SNMP subtree {oid} exceeded {MAX_ROWS_PER_WALK} rows and was truncated.")
        return rows, warnings


def sanitize_credential_profile(credentials: dict[str, Any]) -> dict[str, Any]:
    version = str(credentials.get("version") or "").strip().lower()
    if version == "2c":
        community = str(credentials.get("community") or "")
        if not community:
            raise SnmpCredentialError("SNMPv2c requires an explicit community")
        return {"version": "2c", "security_level": "community"}
    if version != "3":
        raise SnmpCredentialError("Only SNMPv2c and SNMPv3 are supported")

    username = str(credentials.get("username") or "").strip()
    level = str(credentials.get("security_level") or "noAuthNoPriv")
    if not username:
        raise SnmpCredentialError("SNMPv3 requires a username")
    if level not in {"noAuthNoPriv", "authNoPriv", "authPriv"}:
        raise SnmpCredentialError("Unsupported SNMPv3 security level")
    if level in {"authNoPriv", "authPriv"} and not str(credentials.get("auth_password") or ""):
        raise SnmpCredentialError("SNMPv3 authentication password is required")
    if level == "authPriv" and not str(credentials.get("priv_password") or ""):
        raise SnmpCredentialError("SNMPv3 privacy password is required")
    auth_protocol = str(credentials.get("auth_protocol") or "SHA").upper()
    priv_protocol = str(credentials.get("priv_protocol") or "AES").upper()
    if auth_protocol not in {"SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}:
        raise SnmpCredentialError("Unsupported SNMPv3 authentication protocol")
    if priv_protocol not in {"AES", "AES128"}:
        raise SnmpCredentialError("Unsupported SNMPv3 privacy protocol")
    return {
        "version": "3",
        "security_level": level,
        "username": username,
        "auth_protocol": auth_protocol if level != "noAuthNoPriv" else None,
        "priv_protocol": priv_protocol if level == "authPriv" else None,
    }


def _credential_args(credentials: dict[str, Any]) -> tuple[list[str], set[int]]:
    profile = sanitize_credential_profile(credentials)
    args: list[str] = []
    sensitive: set[int] = set()
    if profile["version"] == "2c":
        args.extend(["-v2c", "-c", str(credentials["community"])])
        sensitive.add(2)
        return args, sensitive

    args.extend(["-v3", "-l", str(profile["security_level"]), "-u", str(profile["username"])])
    level = str(profile["security_level"])
    if level in {"authNoPriv", "authPriv"}:
        args.extend(["-a", str(profile["auth_protocol"]), "-A", str(credentials["auth_password"])])
        sensitive.add(len(args) - 1)
    if level == "authPriv":
        proto = "AES" if profile["priv_protocol"] == "AES128" else str(profile["priv_protocol"])
        args.extend(["-x", proto, "-X", str(credentials["priv_password"])])
        sensitive.add(len(args) - 1)
    return args, sensitive


def _target_spec(target: str) -> str:
    parsed = ipaddress.ip_address(target)
    return f"udp:{parsed}:161" if parsed.version == 4 else f"udp6:[{parsed}]:161"


def _parse_output(text: str, *, max_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        if len(rows) >= max_rows:
            break
        line = raw.strip()
        match = re.match(r"^(\.\d+(?:\.\d+)*)\s*=\s*([^:]+):\s*(.*)$", line)
        if not match:
            continue
        oid, value_type, raw_value = match.groups()
        rows.append(
            {
                "oid": oid,
                "type": value_type.strip(),
                "raw": raw_value.strip(),
                "value": _normalize_value(value_type.strip(), raw_value.strip()),
            }
        )
    return rows


def _normalize_value(value_type: str, value: str) -> Any:
    kind = value_type.upper()
    if kind in {"INTEGER", "INTEGER32", "GAUGE32", "UNSIGNED32", "COUNTER32", "COUNTER64"}:
        match = re.search(r"\((-?\d+)\)\s*$", value) or re.match(r"^(-?\d+)", value)
        if match:
            return int(match.group(1))
    if kind == "HEX-STRING":
        octets = []
        for item in value.split():
            try:
                octets.append(int(item, 16))
            except ValueError:
                break
        return {"octets": octets, "hex": "".join(f"{item:02x}" for item in octets)}
    if kind in {"STRING", "OCTET STRING"}:
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
    return value


def _text_value(row: dict[str, Any] | None) -> str | None:
    if not row:
        return None
    value = row.get("value")
    if isinstance(value, str):
        return value.strip() or None
    return str(value) if value is not None else None


def _failure_message(label: str, result: Any) -> str:
    if getattr(result, "cancelled", False):
        return f"SNMP collection cancelled while reading {label}."
    error = getattr(result, "error", None)
    if error is not None:
        code = getattr(error, "code", "error")
        code_value = getattr(code, "value", code)
        return f"SNMP read {label} unavailable: {code_value}."
    return f"SNMP read {label} unavailable."


def normalize_topology_collections(collections: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    interfaces = _interfaces(collections)
    bridge_to_ifindex = {
        suffix[-1]: int(row["value"])
        for row in collections.get("bridge_ports", [])
        if (suffix := _suffix(row["oid"], DOT1D_BASE_PORT_IFINDEX)) and isinstance(row.get("value"), int)
    }
    interface_by_index = {item["ifindex"]: item for item in interfaces}

    pvid_by_port = {
        suffix[-1]: int(row["value"])
        for row in collections.get("pvid", [])
        if (suffix := _suffix(row["oid"], DOT1Q_PVID)) and isinstance(row.get("value"), int)
    }
    vlans, vlan_membership = _vlans(collections)
    for bridge_port, ifindex in bridge_to_ifindex.items():
        item = interface_by_index.get(ifindex)
        if item is None:
            continue
        item["bridge_port"] = bridge_port
        item["pvid"] = pvid_by_port.get(bridge_port)
        member = sorted(vlan_id for vlan_id, ports in vlan_membership.items() if bridge_port in ports)
        item["vlan_ids"] = member

    fdb = _fdb_entries(collections, bridge_to_ifindex, interface_by_index, vlans)
    arp = _arp_entries(collections, interface_by_index)
    lldp = _lldp_entries(collections, interfaces)
    return {
        "interfaces": interfaces,
        "fdb": fdb,
        "arp": arp,
        "lldp_neighbors": lldp,
        "vlans": vlans,
    }


def _interfaces(collections: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    fields = {
        "if_descr": (IF_DESCR, "description"),
        "if_name": (IF_NAME, "name"),
        "if_alias": (IF_ALIAS, "alias"),
        "if_admin": (IF_ADMIN_STATUS, "admin_status"),
        "if_oper": (IF_OPER_STATUS, "oper_status"),
    }
    by_index: dict[int, dict[str, Any]] = {}
    for collection_name, (base, field) in fields.items():
        for row in collections.get(collection_name, []):
            suffix = _suffix(row["oid"], base)
            if not suffix:
                continue
            index = suffix[-1]
            item = by_index.setdefault(index, {"ifindex": index})
            item[field] = row.get("value")
    return [by_index[index] for index in sorted(by_index)]


def _fdb_entries(
    collections: dict[str, list[dict[str, Any]]],
    bridge_to_ifindex: dict[int, int],
    interface_by_index: dict[int, dict[str, Any]],
    vlans: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int | None]] = set()

    # VLAN-aware Q-BRIDGE table index: fdbId + six MAC octets.
    q_by_key: dict[tuple[int, ...], dict[str, Any]] = {}
    for row in collections.get("dot1q_fdb", []):
        suffix = _suffix(row["oid"], DOT1Q_FDB_ENTRY)
        if len(suffix) < 8:
            continue
        column = suffix[0]
        key = tuple(suffix[1:])
        q_by_key.setdefault(key, {})[{1: "mac_value", 2: "bridge_port", 3: "status"}.get(column, f"c{column}")] = row.get("value")
    fdb_to_vlan: dict[int, list[int]] = {}
    for vlan in vlans:
        if vlan.get("fdb_id") is not None:
            fdb_to_vlan.setdefault(int(vlan["fdb_id"]), []).append(int(vlan["vlan_id"]))
    for key, values in q_by_key.items():
        fdb_id = key[0]
        mac = _mac(values.get("mac_value")) or _mac_from_suffix(key[-6:])
        port = values.get("bridge_port")
        if not mac or not isinstance(port, int) or port <= 0:
            continue
        ifindex = bridge_to_ifindex.get(port)
        interface = interface_by_index.get(ifindex or -1, {})
        vlan_ids = sorted(fdb_to_vlan.get(fdb_id, []))
        dedupe = (mac, port, vlan_ids[0] if len(vlan_ids) == 1 else None)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        rows.append({
            "mac": mac,
            "bridge_port": port,
            "ifindex": ifindex,
            "interface_name": interface.get("name") or interface.get("description"),
            "status": values.get("status"),
            "vlan_ids": vlan_ids,
            "source": "q-bridge-fdb",
        })

    # Classic BRIDGE-MIB fallback has no VLAN identity.
    d_by_key: dict[tuple[int, ...], dict[str, Any]] = {}
    for row in collections.get("dot1d_fdb", []):
        suffix = _suffix(row["oid"], DOT1D_FDB_ENTRY)
        if len(suffix) < 7:
            continue
        column = suffix[0]
        key = tuple(suffix[1:])
        d_by_key.setdefault(key, {})[{1: "mac_value", 2: "bridge_port", 3: "status"}.get(column, f"c{column}")] = row.get("value")
    for key, values in d_by_key.items():
        mac = _mac(values.get("mac_value")) or _mac_from_suffix(key[-6:])
        port = values.get("bridge_port")
        if not mac or not isinstance(port, int) or port <= 0:
            continue
        if any(existing[0] == mac and existing[1] == port for existing in seen):
            continue
        ifindex = bridge_to_ifindex.get(port)
        interface = interface_by_index.get(ifindex or -1, {})
        rows.append({
            "mac": mac,
            "bridge_port": port,
            "ifindex": ifindex,
            "interface_name": interface.get("name") or interface.get("description"),
            "status": values.get("status"),
            "vlan_ids": [],
            "source": "bridge-fdb",
        })
    return rows


def _vlans(collections: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[int, set[int]]]:
    by_vlan: dict[int, dict[str, Any]] = {}
    membership: dict[int, set[int]] = {}
    for row in collections.get("vlan_current", []):
        suffix = _suffix(row["oid"], DOT1Q_VLAN_CURRENT_ENTRY)
        if len(suffix) < 3:
            continue
        column = suffix[0]
        vlan_id = suffix[-1]
        item = by_vlan.setdefault(vlan_id, {"vlan_id": vlan_id})
        if column == 3 and isinstance(row.get("value"), int):
            item["fdb_id"] = int(row["value"])
        elif column == 4:
            ports = _port_bitmap(row.get("value"))
            item["egress_ports"] = ports
            membership.setdefault(vlan_id, set()).update(ports)
        elif column == 5:
            item["untagged_ports"] = _port_bitmap(row.get("value"))
    for row in collections.get("vlan_static", []):
        suffix = _suffix(row["oid"], DOT1Q_VLAN_STATIC_ENTRY)
        if len(suffix) < 2:
            continue
        column, vlan_id = suffix[0], suffix[-1]
        item = by_vlan.setdefault(vlan_id, {"vlan_id": vlan_id})
        if column == 1 and isinstance(row.get("value"), str):
            item["name"] = row["value"]
        elif column == 2:
            ports = _port_bitmap(row.get("value"))
            item["static_egress_ports"] = ports
            membership.setdefault(vlan_id, set()).update(ports)
        elif column == 4:
            item["static_untagged_ports"] = _port_bitmap(row.get("value"))
    return [by_vlan[index] for index in sorted(by_vlan)], membership


def _arp_entries(collections: dict[str, list[dict[str, Any]]], interface_by_index: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in collections.get("arp", []):
        suffix = _suffix(row["oid"], IP_NET_TO_MEDIA_PHYS)
        if len(suffix) < 5:
            continue
        ifindex = suffix[0]
        octets = suffix[-4:]
        if any(part < 0 or part > 255 for part in octets):
            continue
        mac = _mac(row.get("value"))
        if not mac:
            continue
        result.append({
            "ip": ".".join(str(part) for part in octets),
            "mac": mac,
            "ifindex": ifindex,
            "interface_name": (interface_by_index.get(ifindex) or {}).get("name"),
        })
    return result


def _lldp_entries(collections: dict[str, list[dict[str, Any]]], interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    local_by_num: dict[int, dict[str, Any]] = {}
    for row in collections.get("lldp_local", []):
        suffix = _suffix(row["oid"], LLDP_LOC_PORT_ENTRY)
        if len(suffix) < 2:
            continue
        column, port_num = suffix[0], suffix[-1]
        local = local_by_num.setdefault(port_num, {"local_port_num": port_num})
        if column == 3:
            local["local_port_id"] = _stringish(row.get("value"))
        elif column == 4:
            local["local_port_description"] = _stringish(row.get("value"))

    interface_names: dict[str, dict[str, Any]] = {}
    for interface in interfaces:
        for key in ("name", "description", "alias"):
            value = str(interface.get(key) or "").strip().lower()
            if value:
                interface_names[value] = interface

    remotes: dict[tuple[int, ...], dict[str, Any]] = {}
    for row in collections.get("lldp_remote", []):
        suffix = _suffix(row["oid"], LLDP_REM_ENTRY)
        if len(suffix) < 4:
            continue
        column = suffix[0]
        key = tuple(suffix[1:])
        item = remotes.setdefault(key, {})
        field = {
            4: "remote_chassis_subtype",
            5: "remote_chassis_id",
            6: "remote_port_subtype",
            7: "remote_port_id",
            8: "remote_port_description",
            9: "remote_system_name",
            10: "remote_system_description",
        }.get(column)
        if field:
            item[field] = _stringish(row.get("value"))

    result: list[dict[str, Any]] = []
    for key, item in remotes.items():
        if len(key) < 3:
            continue
        local_port_num = key[-2]
        local = local_by_num.get(local_port_num, {"local_port_num": local_port_num})
        candidate = str(local.get("local_port_id") or local.get("local_port_description") or "").lower()
        interface = interface_names.get(candidate, {})
        chassis = _mac(item.get("remote_chassis_id")) or item.get("remote_chassis_id")
        result.append({
            **local,
            "local_ifindex": interface.get("ifindex"),
            "local_interface_name": interface.get("name") or interface.get("description"),
            **item,
            "remote_chassis_id": chassis,
        })
    return result


def _suffix(oid: str, base: str) -> list[int]:
    normalized = oid if oid.startswith(".") else f".{oid}"
    if normalized == base:
        return []
    prefix = base + "."
    if not normalized.startswith(prefix):
        return []
    try:
        return [int(part) for part in normalized[len(prefix):].split(".")]
    except ValueError:
        return []


def _mac(value: Any) -> str | None:
    if isinstance(value, dict):
        octets = value.get("octets")
        if isinstance(octets, list) and len(octets) == 6 and all(isinstance(item, int) and 0 <= item <= 255 for item in octets):
            return ":".join(f"{item:02x}" for item in octets)
    if isinstance(value, str):
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(compact) == 12:
            return ":".join(compact[index:index + 2].lower() for index in range(0, 12, 2))
    return None


def _mac_from_suffix(parts: Any) -> str | None:
    values = list(parts)
    if len(values) != 6 or any(not isinstance(item, int) or item < 0 or item > 255 for item in values):
        return None
    return ":".join(f"{item:02x}" for item in values)


def _stringish(value: Any) -> str | None:
    mac = _mac(value)
    if mac:
        return mac
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict) and value.get("hex"):
        return str(value["hex"])
    return str(value) if value is not None else None


def _port_bitmap(value: Any) -> list[int]:
    if not isinstance(value, dict) or not isinstance(value.get("octets"), list):
        return []
    result: list[int] = []
    for byte_index, byte in enumerate(value["octets"]):
        if not isinstance(byte, int):
            continue
        for bit in range(8):
            if byte & (1 << (7 - bit)):
                result.append(byte_index * 8 + bit + 1)
    return result


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
