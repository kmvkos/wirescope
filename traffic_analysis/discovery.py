"""Protocol discovery evidence for retained PCAP analysis.

This pass extracts topology-relevant advertisements separately from ordinary
communications. A discovery frame can support identity or adjacency evidence;
it must never become a topology edge merely because two endpoints exchanged
traffic.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable

from config.settings import Settings, get_settings
from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError
from providers.tools import CancellationToken, ToolCommand, ToolRunner


COMMON_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
)

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "cdp_device_id": ("cdp.deviceid", "cdp.device_id"),
    "cdp_address": ("cdp.address", "cdp.nrgyz.ip_address"),
    "cdp_port_id": ("cdp.portid", "cdp.port_id"),
    "cdp_platform": ("cdp.platform",),
    "cdp_software": ("cdp.software_version", "cdp.softwareversion"),
    "cdp_capabilities": ("cdp.capabilities",),
    "cdp_native_vlan": ("cdp.native_vlan",),
    "lldp_chassis_id": ("lldp.chassis.id", "lldp.chassis_id"),
    "lldp_port_id": ("lldp.port.id", "lldp.port_id"),
    "lldp_port_description": ("lldp.port.desc", "lldp.tlv.port.desc"),
    "lldp_system_name": ("lldp.system.name", "lldp.tlv.system.name"),
    "lldp_system_description": ("lldp.system.desc", "lldp.tlv.system.desc"),
    "lldp_capabilities": (
        "lldp.system.cap",
        "lldp.system.cap.enabled",
        "lldp.tlv.system.cap",
    ),
    "lldp_mgmt_ipv4": (
        "lldp.mgn.addr.ip4",
        "lldp.tlv.mgn.addr.ip4",
        "lldp.management_address.ipv4",
    ),
    "lldp_mgmt_ipv6": (
        "lldp.mgn.addr.ip6",
        "lldp.tlv.mgn.addr.ip6",
        "lldp.management_address.ipv6",
    ),
    "mndp_identity": ("mndp.identity", "mndp.identity_string"),
    "mndp_platform": ("mndp.platform",),
    "mndp_version": ("mndp.version",),
    "mndp_software_id": ("mndp.software_id", "mndp.softwareid"),
    "mndp_interface": ("mndp.interface_name", "mndp.ifname"),
    "mndp_address": ("mndp.address", "mndp.ip"),
    "mndp_mac": ("mndp.mac_address", "mndp.macaddress"),
    "pppoe_code": ("pppoed.code", "pppoe.code"),
    "pppoe_session_id": ("pppoed.sessionid", "pppoe.sessionid"),
    "pppoe_service_name": ("pppoed.tags.service_name", "pppoed.service_name"),
    "pppoe_ac_name": ("pppoed.tags.ac_name", "pppoed.ac_name"),
    "icmpv6_type": ("icmpv6.type",),
    "icmpv6_router_lifetime": ("icmpv6.nd.ra.router_lifetime",),
    "icmpv6_prefix": ("icmpv6.opt.prefix", "icmpv6.nd.ra.prefix"),
    "icmpv6_prefix_len": ("icmpv6.opt.prefix_len", "icmpv6.nd.ra.prefix_len"),
    "icmpv6_source_linkaddr": (
        "icmpv6.opt.src_linkaddr",
        "icmpv6.opt.source_linkaddr",
        "icmpv6.nd.opt.source_linkaddr",
    ),
    "icmpv6_target_linkaddr": (
        "icmpv6.opt.tgt_linkaddr",
        "icmpv6.opt.target_linkaddr",
        "icmpv6.nd.opt.target_linkaddr",
    ),
    "dhcp_message_type": ("dhcp.option.dhcp", "bootp.option.dhcp"),
    "dhcp_client_mac": ("dhcp.hw.mac_addr", "bootp.hw.mac_addr"),
    "dhcp_hostname": ("dhcp.option.hostname", "bootp.option.hostname"),
    "dhcp_server_id": (
        "dhcp.option.dhcp_server_id",
        "bootp.option.dhcp_server_id",
    ),
    "dhcp_your_ip": ("dhcp.ip.your", "bootp.ip.your"),
    "dhcp_router": ("dhcp.option.router", "bootp.option.router"),
    "dhcp_dns": (
        "dhcp.option.domain_name_server",
        "bootp.option.domain_name_server",
    ),
    "dhcp_subnet_mask": ("dhcp.option.subnet_mask", "bootp.option.subnet_mask"),
}

FIELD_CANDIDATES: tuple[str, ...] = tuple(
    dict.fromkeys(
        [
            *COMMON_FIELDS,
            *[field for aliases in FIELD_ALIASES.values() for field in aliases],
        ]
    )
)

_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_DHCP_TYPES = {
    "1": "DISCOVER",
    "2": "OFFER",
    "3": "REQUEST",
    "4": "DECLINE",
    "5": "ACK",
    "6": "NAK",
    "7": "RELEASE",
    "8": "INFORM",
}
_PPPOE_CODES = {0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xA7: "PADT"}
_CDP_CAPABILITIES = {
    0x01: "router",
    0x02: "transparent_bridge",
    0x04: "source_route_bridge",
    0x08: "switch",
    0x10: "host",
    0x20: "igmp",
    0x40: "repeater",
    0x80: "voip_phone",
}
_LLDP_CAPABILITIES = {
    0x0001: "other",
    0x0002: "repeater",
    0x0004: "bridge",
    0x0008: "wlan_access_point",
    0x0010: "router",
    0x0020: "telephone",
    0x0040: "docsis",
    0x0080: "station",
    0x0100: "c_vlan",
    0x0200: "s_vlan",
    0x0400: "two_port_mac_relay",
}


def _safe_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _valid_mac(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().lower()
    parts = text.split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return None
    if text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or octets[0] & 0x01:
        return None
    return text


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _first_value(raw: str) -> str:
    return raw.strip().split(",", 1)[0].strip()


def _parse_int(raw: str) -> int | None:
    text = raw.strip().lower()
    if not text:
        return None
    token = text.split()[0].strip("(),")
    try:
        return int(token, 16) if token.startswith("0x") else int(token)
    except ValueError:
        return None


def _roles_from_capabilities(raw: str, mapping: dict[int, str]) -> list[str]:
    roles: set[str] = set()
    numeric = _parse_int(raw)
    if numeric is not None:
        for bit, role in mapping.items():
            if numeric & bit:
                roles.add(role)
    lowered = raw.lower()
    for needle, role in {
        "router": "router",
        "switch": "switch",
        "bridge": "bridge",
        "host": "host",
        "wlan": "wlan_access_point",
        "telephone": "telephone",
        "phone": "voip_phone",
        "repeater": "repeater",
    }.items():
        if needle in lowered:
            roles.add(role)
    return sorted(roles)


def _dhcp_type(raw: str) -> str | None:
    text = raw.strip().upper()
    if not text:
        return None
    if text in _DHCP_TYPES.values():
        return text
    token = text.split()[0].strip("(),")
    if token in _DHCP_TYPES:
        return _DHCP_TYPES[token]
    for label in _DHCP_TYPES.values():
        if label in text:
            return label
    return text


def _pppoe_code(raw: str) -> str | None:
    numeric = _parse_int(raw)
    if numeric is not None:
        return _PPPOE_CODES.get(numeric, f"0x{numeric:02x}")
    text = raw.strip().upper()
    if not text:
        return None
    for label in _PPPOE_CODES.values():
        if label in text:
            return label
    return text


def _merge_time(item: dict[str, Any], timestamp: float | None) -> None:
    if timestamp is None:
        return
    first = item.get("first_seen")
    last = item.get("last_seen")
    item["first_seen"] = timestamp if first is None else min(float(first), timestamp)
    item["last_seen"] = timestamp if last is None else max(float(last), timestamp)


def _device_row(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": item["protocol"],
        "source_mac": item.get("source_mac"),
        "addresses": sorted(item.get("addresses") or []),
        "names": sorted(item.get("names") or []),
        "platform": item.get("platform"),
        "software": item.get("software"),
        "port_id": item.get("port_id"),
        "port_description": item.get("port_description"),
        "capabilities_raw": item.get("capabilities_raw"),
        "roles": sorted(item.get("roles") or []),
        "native_vlan": item.get("native_vlan"),
        "frames": int(item.get("frames") or 0),
        "first_seen": _iso(item.get("first_seen")),
        "last_seen": _iso(item.get("last_seen")),
        "confidence": "high",
        "provenance": item["protocol"],
    }


class DiscoveryEvidenceAnalyzer:
    """Extract topology-specific discovery/configuration evidence."""

    def __init__(self, *, runner: ToolRunner | None = None, settings: Settings | None = None) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()

    def _supported_fields(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None,
    ) -> set[str]:
        fd, name = tempfile.mkstemp(
            prefix="tshark-discovery-fields-", suffix=".txt", dir=pcap_path.parent
        )
        os.close(fd)
        path = Path(name)
        path.chmod(0o600)
        try:
            result = self.runner.run(
                ToolCommand(
                    tool=self.settings.tshark_binary,
                    args=["-G", "fields"],
                    timeout_seconds=90,
                    stdout_path=path,
                    environment={"LC_ALL": "C"},
                ),
                cancellation_token=cancellation_token,
            )
            if not result.success:
                category = ErrorCategory.CANCELLED if result.cancelled else ErrorCategory.INTERNAL
                if result.error and result.error.code.value == "missing_binary":
                    category = ErrorCategory.TOOL_MISSING
                raise JobExecutionError(
                    JobError(
                        code="discovery_field_probe_failed",
                        category=category,
                        message=(
                            result.error.message
                            if result.error
                            else "tshark discovery field probe failed"
                        ),
                        component="traffic_analysis",
                        details={"exit_code": result.exit_code},
                    )
                )
            supported: set[str] = set()
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for raw in stream:
                    columns = raw.rstrip("\r\n").split("\t")
                    if len(columns) >= 3 and columns[0] == "F" and columns[2]:
                        supported.add(columns[2])
            return supported
        finally:
            path.unlink(missing_ok=True)

    def analyze(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        if progress:
            progress(75, "Определяем поля discovery-протоколов")
        supported = self._supported_fields(pcap_path, cancellation_token=cancellation_token)
        selected = [name for name in FIELD_CANDIDATES if name in supported]
        if "frame.protocols" not in selected:
            raise JobExecutionError(
                JobError(
                    code="discovery_fields_unavailable",
                    category=ErrorCategory.INTERNAL,
                    message="Installed tshark does not expose frame.protocols",
                    component="traffic_analysis",
                )
            )

        fd, name = tempfile.mkstemp(
            prefix="traffic-discovery-", suffix=".tsv", dir=pcap_path.parent
        )
        os.close(fd)
        output_path = Path(name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(76, "Разбираем CDP, LLDP, MNDP, PPPoE, IPv6 ND/RA и DHCP")
            args = [
                "-r", str(pcap_path), "-n", "-T", "fields",
                "-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n",
            ]
            for field in selected:
                args.extend(["-e", field])
            result = self.runner.run(
                ToolCommand(
                    tool=self.settings.tshark_binary,
                    args=args,
                    timeout_seconds=900,
                    stdout_path=output_path,
                    environment={"LC_ALL": "C"},
                ),
                cancellation_token=cancellation_token,
            )
            if not result.success:
                category = ErrorCategory.INTERNAL
                code = "discovery_decode_failed"
                if result.cancelled:
                    category = ErrorCategory.CANCELLED
                    code = "cancelled"
                elif result.timed_out:
                    category = ErrorCategory.TIMEOUT
                    code = "discovery_decode_timeout"
                elif result.error and result.error.code.value == "missing_binary":
                    category = ErrorCategory.TOOL_MISSING
                    code = "tshark_unavailable"
                raise JobExecutionError(
                    JobError(
                        code=code,
                        category=category,
                        message=(result.error.message if result.error else "tshark discovery decode failed"),
                        component="traffic_analysis",
                        details={"exit_code": result.exit_code},
                    )
                )
            with output_path.open("r", encoding="utf-8", errors="replace") as stream:
                document = self.analyze_tsv(stream, fields=selected, progress=progress)
            document["field_coverage"] = {
                "supported_requested": selected,
                "missing_optional": [name for name in FIELD_CANDIDATES if name not in supported],
            }
            return document
        finally:
            output_path.unlink(missing_ok=True)

    def analyze_tsv(
        self,
        lines: Iterable[str],
        *,
        fields: list[str] | tuple[str, ...],
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        index = {name: position for position, name in enumerate(fields)}

        def raw_value(columns: list[str], field: str) -> str:
            position = index.get(field)
            return columns[position].strip() if position is not None and position < len(columns) else ""

        def value(columns: list[str], semantic: str) -> str:
            for field in FIELD_ALIASES.get(semantic, (semantic,)):
                result = raw_value(columns, field)
                if result:
                    return result
            return ""

        devices: dict[tuple[str, str], dict[str, Any]] = {}
        pppoe_codes: Counter[str] = Counter()
        pppoe_sources: Counter[str] = Counter()
        pppoe_services: Counter[str] = Counter()
        pppoe_access_concentrators: Counter[str] = Counter()
        ra_routers: dict[tuple[str, str], dict[str, Any]] = {}
        nd_neighbors: dict[tuple[str, str], dict[str, Any]] = {}
        ra_prefixes: Counter[str] = Counter()
        dhcp_messages: Counter[str] = Counter()
        dhcp_servers: Counter[str] = Counter()
        dhcp_routers: Counter[str] = Counter()
        dhcp_dns: Counter[str] = Counter()
        dhcp_assignments: dict[tuple[str, str], dict[str, Any]] = {}
        identity_links: dict[tuple[str, str], dict[str, Any]] = {}

        def note_identity(
            ip_value: str | None,
            mac_value: str | None,
            *,
            evidence_type: str,
            confidence: str,
            timestamp: float | None,
        ) -> None:
            ip_text = _safe_ip(ip_value or "")
            mac_text = _valid_mac(mac_value)
            if not ip_text or not mac_text:
                return
            key = (ip_text, mac_text)
            item = identity_links.setdefault(
                key,
                {
                    "ip": ip_text,
                    "mac": mac_text,
                    "confidence": confidence,
                    "evidence": Counter(),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                },
            )
            item["evidence"][evidence_type] += 1
            if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(str(item["confidence"]), 0):
                item["confidence"] = confidence
            _merge_time(item, timestamp)

        def discovery_device(
            protocol: str,
            *,
            source_mac: str | None,
            identifier: str | None,
            address: str | None,
            timestamp: float | None,
        ) -> dict[str, Any]:
            identity = source_mac or identifier or address or "unknown"
            key = (protocol, identity)
            item = devices.setdefault(
                key,
                {
                    "protocol": protocol,
                    "source_mac": source_mac,
                    "addresses": set(),
                    "names": set(),
                    "platform": None,
                    "software": None,
                    "port_id": None,
                    "port_description": None,
                    "capabilities_raw": None,
                    "roles": set(),
                    "native_vlan": None,
                    "frames": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                },
            )
            item["frames"] += 1
            if identifier:
                item["names"].add(identifier)
            if address:
                item["addresses"].add(address)
            _merge_time(item, timestamp)
            return item

        for row_number, raw in enumerate(lines, start=1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) < len(fields):
                columns.extend([""] * (len(fields) - len(columns)))

            timestamp = _float(raw_value(columns, "frame.time_epoch"))
            protocols = {
                item.strip().lower()
                for item in raw_value(columns, "frame.protocols").split(":")
                if item.strip()
            }
            source_mac = _valid_mac(raw_value(columns, "eth.src"))
            source_ip = _safe_ip(raw_value(columns, "ip.src")) or _safe_ip(raw_value(columns, "ipv6.src"))

            cdp_id = value(columns, "cdp_device_id")
            cdp_address = _safe_ip(_first_value(value(columns, "cdp_address")))
            if "cdp" in protocols or cdp_id or cdp_address:
                item = discovery_device(
                    "cdp", source_mac=source_mac, identifier=cdp_id or None,
                    address=cdp_address, timestamp=timestamp,
                )
                item["platform"] = value(columns, "cdp_platform") or item["platform"]
                item["software"] = value(columns, "cdp_software") or item["software"]
                item["port_id"] = value(columns, "cdp_port_id") or item["port_id"]
                capabilities = value(columns, "cdp_capabilities")
                if capabilities:
                    item["capabilities_raw"] = capabilities
                    item["roles"].update(_roles_from_capabilities(capabilities, _CDP_CAPABILITIES))
                native_vlan = value(columns, "cdp_native_vlan")
                if native_vlan:
                    item["native_vlan"] = native_vlan
                if cdp_address and source_mac:
                    note_identity(
                        cdp_address, source_mac, evidence_type="cdp_advertisement",
                        confidence="high", timestamp=timestamp,
                    )

            lldp_name = value(columns, "lldp_system_name")
            lldp_chassis = value(columns, "lldp_chassis_id")
            lldp_address = (
                _safe_ip(_first_value(value(columns, "lldp_mgmt_ipv4")))
                or _safe_ip(_first_value(value(columns, "lldp_mgmt_ipv6")))
            )
            if "lldp" in protocols or lldp_name or lldp_chassis or lldp_address:
                item = discovery_device(
                    "lldp", source_mac=source_mac,
                    identifier=lldp_name or lldp_chassis or None,
                    address=lldp_address, timestamp=timestamp,
                )
                if lldp_name:
                    item["names"].add(lldp_name)
                item["software"] = value(columns, "lldp_system_description") or item["software"]
                item["port_id"] = value(columns, "lldp_port_id") or item["port_id"]
                item["port_description"] = value(columns, "lldp_port_description") or item["port_description"]
                capabilities = value(columns, "lldp_capabilities")
                if capabilities:
                    item["capabilities_raw"] = capabilities
                    item["roles"].update(_roles_from_capabilities(capabilities, _LLDP_CAPABILITIES))
                if lldp_address and source_mac:
                    note_identity(
                        lldp_address, source_mac, evidence_type="lldp_management",
                        confidence="high", timestamp=timestamp,
                    )

            mndp_identity = value(columns, "mndp_identity")
            mndp_mac = _valid_mac(value(columns, "mndp_mac")) or source_mac
            mndp_address = _safe_ip(_first_value(value(columns, "mndp_address")))
            if "mndp" in protocols or "mikrotik" in protocols or mndp_identity or mndp_address:
                item = discovery_device(
                    "mndp", source_mac=mndp_mac, identifier=mndp_identity or None,
                    address=mndp_address or source_ip, timestamp=timestamp,
                )
                item["platform"] = value(columns, "mndp_platform") or item["platform"]
                version = value(columns, "mndp_version")
                software_id = value(columns, "mndp_software_id")
                software = " ".join(part for part in (software_id, version) if part).strip()
                if software:
                    item["software"] = software
                item["port_id"] = value(columns, "mndp_interface") or item["port_id"]
                item["roles"].add("network_device")
                advertised = mndp_address or source_ip
                if advertised and mndp_mac:
                    note_identity(
                        advertised, mndp_mac, evidence_type="mndp_advertisement",
                        confidence="high", timestamp=timestamp,
                    )

            pppoe_label = _pppoe_code(value(columns, "pppoe_code"))
            if "pppoed" in protocols or pppoe_label:
                label = pppoe_label or "discovery"
                pppoe_codes[label] += 1
                if source_mac:
                    pppoe_sources[source_mac] += 1
                service = value(columns, "pppoe_service_name")
                ac_name = value(columns, "pppoe_ac_name")
                if service:
                    pppoe_services[service] += 1
                if ac_name:
                    pppoe_access_concentrators[ac_name] += 1

            icmpv6_type = _parse_int(value(columns, "icmpv6_type"))
            if "icmpv6" in protocols and icmpv6_type in {133, 134, 135, 136}:
                link_mac = (
                    _valid_mac(value(columns, "icmpv6_source_linkaddr"))
                    or _valid_mac(value(columns, "icmpv6_target_linkaddr"))
                    or source_mac
                )
                if icmpv6_type == 134 and source_ip:
                    key = (source_ip, link_mac or "")
                    item = ra_routers.setdefault(
                        key,
                        {
                            "address": source_ip, "mac": link_mac, "frames": 0,
                            "router_lifetime": None, "prefixes": set(),
                            "first_seen": timestamp, "last_seen": timestamp,
                        },
                    )
                    item["frames"] += 1
                    lifetime = _parse_int(value(columns, "icmpv6_router_lifetime"))
                    if lifetime is not None:
                        item["router_lifetime"] = lifetime
                    prefix = _safe_ip(value(columns, "icmpv6_prefix"))
                    prefix_len = _parse_int(value(columns, "icmpv6_prefix_len"))
                    if prefix and prefix_len is not None and 0 <= prefix_len <= 128:
                        network = str(ipaddress.ip_network(f"{prefix}/{prefix_len}", strict=False))
                        item["prefixes"].add(network)
                        ra_prefixes[network] += 1
                    _merge_time(item, timestamp)
                    if link_mac:
                        note_identity(
                            source_ip, link_mac, evidence_type="router_advertisement",
                            confidence="high", timestamp=timestamp,
                        )
                elif icmpv6_type == 136 and source_ip:
                    key = (source_ip, link_mac or "")
                    item = nd_neighbors.setdefault(
                        key,
                        {
                            "address": source_ip, "mac": link_mac, "frames": 0,
                            "first_seen": timestamp, "last_seen": timestamp,
                        },
                    )
                    item["frames"] += 1
                    _merge_time(item, timestamp)
                    if link_mac:
                        note_identity(
                            source_ip, link_mac, evidence_type="nd_advertisement",
                            confidence="high", timestamp=timestamp,
                        )

            dhcp_message = _dhcp_type(value(columns, "dhcp_message_type"))
            if "dhcp" in protocols or "bootp" in protocols or dhcp_message:
                if dhcp_message:
                    dhcp_messages[dhcp_message] += 1
                server = _safe_ip(value(columns, "dhcp_server_id"))
                if server:
                    dhcp_servers[server] += 1
                router = _safe_ip(_first_value(value(columns, "dhcp_router")))
                if router:
                    dhcp_routers[router] += 1
                dns_server = _safe_ip(_first_value(value(columns, "dhcp_dns")))
                if dns_server:
                    dhcp_dns[dns_server] += 1
                offered = _safe_ip(value(columns, "dhcp_your_ip"))
                client_mac = _valid_mac(value(columns, "dhcp_client_mac"))
                if (
                    offered and offered not in {"0.0.0.0", "255.255.255.255"}
                    and client_mac and dhcp_message in {"OFFER", "ACK"}
                ):
                    key = (offered, client_mac)
                    item = dhcp_assignments.setdefault(
                        key,
                        {
                            "address": offered, "mac": client_mac, "hostname": None,
                            "server": server, "message_types": Counter(), "frames": 0,
                            "first_seen": timestamp, "last_seen": timestamp,
                        },
                    )
                    item["frames"] += 1
                    item["message_types"][dhcp_message] += 1
                    hostname = value(columns, "dhcp_hostname")
                    if hostname:
                        item["hostname"] = hostname
                    if server:
                        item["server"] = server
                    _merge_time(item, timestamp)
                    note_identity(
                        offered,
                        client_mac,
                        evidence_type=(
                            "dhcp_ack_assignment" if dhcp_message == "ACK"
                            else "dhcp_offer_assignment"
                        ),
                        confidence="high",
                        timestamp=timestamp,
                    )

            if progress and row_number % 50_000 == 0:
                progress(77, f"Discovery evidence: обработано {row_number:,} кадров")

        device_rows = [_device_row(item) for item in devices.values()]
        device_rows.sort(key=lambda item: (item["protocol"], -int(item["frames"]), item["source_mac"] or ""))

        identity_rows = [
            {
                "ip": item["ip"],
                "mac": item["mac"],
                "confidence": item["confidence"],
                "evidence": [
                    {"type": name, "count": count}
                    for name, count in item["evidence"].most_common()
                ],
                "first_seen": _iso(item.get("first_seen")),
                "last_seen": _iso(item.get("last_seen")),
            }
            for item in identity_links.values()
        ]
        identity_rows.sort(
            key=lambda item: (
                _CONFIDENCE_RANK.get(str(item["confidence"]), 0),
                sum(int(e.get("count") or 0) for e in item["evidence"]),
            ),
            reverse=True,
        )

        ra_rows = [
            {
                "address": item["address"], "mac": item["mac"], "frames": item["frames"],
                "router_lifetime": item["router_lifetime"], "prefixes": sorted(item["prefixes"]),
                "first_seen": _iso(item.get("first_seen")), "last_seen": _iso(item.get("last_seen")),
                "confidence": "high",
            }
            for item in ra_routers.values()
        ]
        neighbor_rows = [
            {
                "address": item["address"], "mac": item["mac"], "frames": item["frames"],
                "first_seen": _iso(item.get("first_seen")), "last_seen": _iso(item.get("last_seen")),
                "confidence": "high",
            }
            for item in nd_neighbors.values()
        ]
        assignment_rows = [
            {
                "address": item["address"], "mac": item["mac"], "hostname": item["hostname"],
                "server": item["server"], "message_types": dict(item["message_types"]),
                "frames": item["frames"], "first_seen": _iso(item.get("first_seen")),
                "last_seen": _iso(item.get("last_seen")), "confidence": "high",
            }
            for item in dhcp_assignments.values()
        ]

        return {
            "schema": "traffic-discovery-evidence",
            "schema_version": 1,
            "devices": device_rows,
            "cdp": {
                "frames": sum(item["frames"] for item in device_rows if item["protocol"] == "cdp"),
                "devices": [item for item in device_rows if item["protocol"] == "cdp"],
            },
            "lldp": {
                "frames": sum(item["frames"] for item in device_rows if item["protocol"] == "lldp"),
                "devices": [item for item in device_rows if item["protocol"] == "lldp"],
            },
            "mndp": {
                "frames": sum(item["frames"] for item in device_rows if item["protocol"] == "mndp"),
                "devices": [item for item in device_rows if item["protocol"] == "mndp"],
            },
            "pppoe": {
                "frames": sum(pppoe_codes.values()),
                "codes": [{"code": name, "frames": count} for name, count in pppoe_codes.most_common()],
                "sources": [{"mac": name, "frames": count} for name, count in pppoe_sources.most_common(20)],
                "service_names": [{"name": name, "frames": count} for name, count in pppoe_services.most_common(20)],
                "access_concentrators": [{"name": name, "frames": count} for name, count in pppoe_access_concentrators.most_common(20)],
                "topology_semantics": "discovery_activity_only",
            },
            "ipv6_nd": {
                "router_advertisements": ra_rows,
                "neighbor_advertisements": neighbor_rows,
                "prefixes": [{"prefix": name, "frames": count} for name, count in ra_prefixes.most_common()],
            },
            "dhcp": {
                "messages": [{"type": name, "frames": count} for name, count in dhcp_messages.most_common()],
                "servers": [{"endpoint": name, "frames": count} for name, count in dhcp_servers.most_common(20)],
                "assignments": assignment_rows,
                "advertised_routers": [{"endpoint": name, "frames": count} for name, count in dhcp_routers.most_common(20)],
                "advertised_dns": [{"endpoint": name, "frames": count} for name, count in dhcp_dns.most_common(20)],
            },
            "identity_links": identity_rows,
            "topology_evidence": {
                "discovery_devices": device_rows,
                "routers": ra_rows,
                "neighbors": neighbor_rows,
                "dhcp_assignments": assignment_rows,
            },
            "network_configuration": {
                "dhcp_advertised_routers": [item for item, _count in dhcp_routers.most_common()],
                "dhcp_advertised_dns": [item for item, _count in dhcp_dns.most_common()],
                "ipv6_advertised_prefixes": [item for item, _count in ra_prefixes.most_common()],
            },
            "limitations": [
                "Discovery advertisements describe what a device claims about itself; they do not by themselves prove an end-to-end physical cable path.",
                "PPPoE discovery is retained as L2 activity evidence and is not converted into a host or topology edge.",
                "Optional tshark fields vary by Wireshark version; field_coverage records which metadata was unavailable.",
            ],
        }


def _merge_identity_links(
    existing: list[dict[str, Any]],
    added: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in [*existing, *added]:
        ip_value = str(source.get("ip") or "")
        mac_value = str(source.get("mac") or "").lower()
        if not ip_value or not mac_value:
            continue
        key = (ip_value, mac_value)
        item = merged.setdefault(
            key,
            {
                "ip": ip_value, "mac": mac_value, "confidence": "none",
                "evidence": Counter(), "first_seen": source.get("first_seen"),
                "last_seen": source.get("last_seen"),
            },
        )
        confidence = str(source.get("confidence") or "none")
        if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(str(item["confidence"]), 0):
            item["confidence"] = confidence
        for evidence in source.get("evidence") or []:
            evidence_type = str(evidence.get("type") or "unknown")
            item["evidence"][evidence_type] += int(evidence.get("count") or 0)
        first = source.get("first_seen")
        last = source.get("last_seen")
        if first:
            item["first_seen"] = first if not item.get("first_seen") else min(str(item["first_seen"]), str(first))
        if last:
            item["last_seen"] = last if not item.get("last_seen") else max(str(item["last_seen"]), str(last))

    rows = [
        {
            "ip": item["ip"], "mac": item["mac"], "confidence": item["confidence"],
            "evidence": [{"type": name, "count": count} for name, count in item["evidence"].most_common()],
            "first_seen": item.get("first_seen"), "last_seen": item.get("last_seen"),
        }
        for item in merged.values()
    ]
    rows.sort(
        key=lambda item: (
            _CONFIDENCE_RANK.get(str(item["confidence"]), 0),
            sum(int(e.get("count") or 0) for e in item["evidence"]),
        ),
        reverse=True,
    )
    return rows


def merge_discovery_evidence(document: dict[str, Any], discovery: dict[str, Any]) -> dict[str, Any]:
    """Attach discovery output and promote only explicit identity evidence."""
    document["discovery_evidence"] = discovery
    identity = dict(document.get("identity_observations") or {})
    identity["links"] = _merge_identity_links(
        list(identity.get("links") or []),
        list(discovery.get("identity_links") or []),
    )
    identity["link_count"] = len(identity["links"])
    document["identity_observations"] = identity
    network_config = dict(document.get("network_configuration") or {})
    network_config.update(discovery.get("network_configuration") or {})
    document["network_configuration"] = network_config
    return document
