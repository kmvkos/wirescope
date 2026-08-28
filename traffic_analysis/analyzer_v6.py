"""Evidence-driven additive layer for retained PCAP analysis.

Version 6 deliberately preserves the v5 result shape and augments it with raw-ish
identity, ARP and directional-flow evidence.  The topology layer can therefore
consume stronger facts without treating every observed endpoint or conversation
as a physical/logical adjacency.

This module is intentionally additive during the migration.  The mature v5
analyzer remains the implementation for existing diagnostics; this class taps the
same decoded TSV stream and adds evidence semantics in one streaming pass.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
import re
from typing import Any, Callable, Iterable, Iterator

from traffic_analysis.analyzer import (
    DOMINANT_PROTOCOLS,
    FIELDS,
    TrafficAnalyzer as _LegacyTrafficAnalyzer,
    _endpoint,
    _float,
    _is_broadcast,
    _is_multicast,
    _iso,
    _number,
    _safe_ip,
)


_SERVICE_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    389,
    443,
    445,
    465,
    514,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5353,
    5355,
    5672,
    6379,
    8080,
    8443,
    9200,
    27017,
}

_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def _dominant_protocol(protocols: list[str]) -> str:
    return next(
        (name for name in DOMINANT_PROTOCOLS if name in protocols),
        protocols[-1] if protocols else "other",
    )


def _valid_identity_mac(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if lowered in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return False
    try:
        first_octet = int(lowered.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return not bool(first_octet & 0x01)


def _is_unicast_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        parsed.is_multicast
        or parsed.is_unspecified
        or (parsed.version == 4 and value == "255.255.255.255")
    )


def _is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(parsed.is_global)


def _private_prefix_hint(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if parsed.version != 4 or not parsed.is_private:
        return None
    # /24 is explicitly a presentation hint, not an inferred subnet mask.
    return str(ipaddress.ip_network(f"{parsed}/24", strict=False))


def _service_role_hint(src_port: str, dst_port: str) -> dict[str, Any]:
    src = _number(src_port, -1)
    dst = _number(dst_port, -1)
    if dst in _SERVICE_PORTS and src not in _SERVICE_PORTS:
        return {
            "client_side": "source",
            "server_side": "destination",
            "service_port": dst,
            "confidence": "low",
            "basis": "well_known_destination_port",
        }
    if src in _SERVICE_PORTS and dst not in _SERVICE_PORTS:
        return {
            "client_side": "destination",
            "server_side": "source",
            "service_port": src,
            "confidence": "low",
            "basis": "well_known_source_port",
        }
    return {
        "client_side": "unknown",
        "server_side": "unknown",
        "service_port": None,
        "confidence": "none",
        "basis": "insufficient_evidence",
    }


class TrafficAnalyzer(_LegacyTrafficAnalyzer):
    """v5 diagnostics plus evidence suitable for identity/topology correlation."""

    def analyze_tsv(
        self,
        lines: Iterable[str],
        *,
        source: dict[str, Any],
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        index = {name: position for position, name in enumerate(FIELDS)}

        identity_links: dict[tuple[str, str], dict[str, Any]] = {}
        endpoint_roles: defaultdict[str, Counter[str]] = defaultdict(Counter)
        flow_items: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        private_prefixes: Counter[str] = Counter()
        observed_vlan_tags: Counter[str] = Counter()
        arp_requests = 0
        arp_replies = 0
        arp_probed_targets: Counter[str] = Counter()
        arp_confirmed_responders: Counter[str] = Counter()

        def field(columns: list[str], name: str) -> str:
            position = index[name]
            return columns[position].strip() if position < len(columns) else ""

        def note_identity(
            ip_value: str | None,
            mac_value: str | None,
            *,
            evidence_type: str,
            confidence: str,
            timestamp: float | None,
        ) -> None:
            if not _is_unicast_ip(ip_value) or not _valid_identity_mac(mac_value):
                return
            ip_text = str(ip_value)
            mac_text = str(mac_value).lower()
            key = (ip_text, mac_text)
            item = identity_links.setdefault(
                key,
                {
                    "ip": ip_text,
                    "mac": mac_text,
                    "evidence": Counter(),
                    "confidence": confidence,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                },
            )
            item["evidence"][evidence_type] += 1
            if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(
                str(item["confidence"]), 0
            ):
                item["confidence"] = confidence
            if timestamp is not None:
                item["first_seen"] = (
                    timestamp
                    if item["first_seen"] is None
                    else min(float(item["first_seen"]), timestamp)
                )
                item["last_seen"] = (
                    timestamp
                    if item["last_seen"] is None
                    else max(float(item["last_seen"]), timestamp)
                )

        def mark_endpoint(endpoint: str | None, role: str) -> None:
            if endpoint:
                endpoint_roles[endpoint][role] += 1

        def tapped() -> Iterator[str]:
            nonlocal arp_requests, arp_replies

            for raw in lines:
                line = raw.rstrip("\r\n")
                if not line:
                    yield raw
                    continue
                columns = line.split("\t")
                if len(columns) < len(FIELDS):
                    columns.extend([""] * (len(FIELDS) - len(columns)))

                timestamp = _float(field(columns, "frame.time_epoch"))
                frame_len = _number(field(columns, "frame.len"))
                source_mac = field(columns, "eth.src").lower() or None
                destination_mac = field(columns, "eth.dst").lower() or None
                source_ip = _safe_ip(field(columns, "ip.src")) or _safe_ip(
                    field(columns, "ipv6.src")
                )
                destination_ip = _safe_ip(field(columns, "ip.dst")) or _safe_ip(
                    field(columns, "ipv6.dst")
                )
                protocols = [
                    item.strip().lower()
                    for item in field(columns, "frame.protocols").split(":")
                    if item.strip()
                ]
                dominant = _dominant_protocol(protocols)

                vlan = field(columns, "vlan.id")
                if vlan:
                    observed_vlan_tags[vlan] += 1

                # Source L3/L2 pairing is useful evidence but is deliberately only
                # medium confidence: at a routed capture point the Ethernet source
                # may be an immediate next-hop rather than the original IP asset.
                if source_ip and source_mac:
                    note_identity(
                        source_ip,
                        source_mac,
                        evidence_type="ethernet_ip_source",
                        confidence="medium",
                        timestamp=timestamp,
                    )

                src_endpoint, _src_kind = _endpoint(source_ip, source_mac)
                dst_endpoint, _dst_kind = _endpoint(destination_ip, destination_mac)
                if src_endpoint:
                    if source_ip and _is_external_ip(source_ip):
                        mark_endpoint(src_endpoint, "external_peer")
                    else:
                        mark_endpoint(src_endpoint, "observed_sender")

                is_broadcast = _is_broadcast(destination_ip, destination_mac)
                is_multicast = _is_multicast(destination_ip, destination_mac)
                if dst_endpoint and not is_broadcast and not is_multicast:
                    if destination_ip and _is_external_ip(destination_ip):
                        mark_endpoint(dst_endpoint, "external_peer")
                    else:
                        mark_endpoint(dst_endpoint, "observed_peer")

                for address in (source_ip, destination_ip):
                    hint = _private_prefix_hint(address)
                    if hint:
                        private_prefixes[hint] += 1

                arp_opcode = field(columns, "arp.opcode")
                arp_source_ip = _safe_ip(field(columns, "arp.src.proto_ipv4"))
                arp_source_mac = field(columns, "arp.src.hw_mac").lower() or None
                arp_target_ip = _safe_ip(field(columns, "arp.dst.proto_ipv4"))
                if arp_source_ip and arp_source_mac:
                    note_identity(
                        arp_source_ip,
                        arp_source_mac,
                        evidence_type=(
                            "arp_reply_sender" if arp_opcode == "2" else "arp_request_sender"
                        ),
                        confidence="high" if arp_opcode == "2" else "medium",
                        timestamp=timestamp,
                    )
                    mark_endpoint(arp_source_ip, "observed_sender")

                if arp_opcode == "1":
                    arp_requests += 1
                    if arp_target_ip and arp_target_ip != arp_source_ip:
                        arp_probed_targets[arp_target_ip] += 1
                        mark_endpoint(arp_target_ip, "probed_target")
                elif arp_opcode == "2":
                    arp_replies += 1
                    if arp_source_ip:
                        arp_confirmed_responders[arp_source_ip] += 1
                        mark_endpoint(arp_source_ip, "confirmed_responder")

                tcp_src = field(columns, "tcp.srcport")
                tcp_dst = field(columns, "tcp.dstport")
                udp_src = field(columns, "udp.srcport")
                udp_dst = field(columns, "udp.dstport")
                transport = "tcp" if tcp_src or tcp_dst else "udp" if udp_src or udp_dst else ""
                source_port = tcp_src or udp_src
                destination_port = tcp_dst or udp_dst

                if transport and src_endpoint and dst_endpoint and src_endpoint != dst_endpoint:
                    key = (
                        src_endpoint,
                        source_port,
                        dst_endpoint,
                        destination_port,
                        transport,
                    )
                    item = flow_items.setdefault(
                        key,
                        {
                            "src_endpoint": src_endpoint,
                            "dst_endpoint": dst_endpoint,
                            "src_ip": source_ip,
                            "dst_ip": destination_ip,
                            "src_mac": source_mac,
                            "dst_mac": destination_mac,
                            "src_port": _number(source_port, 0) or None,
                            "dst_port": _number(destination_port, 0) or None,
                            "transport": transport,
                            "packets": 0,
                            "bytes": 0,
                            "protocols": Counter(),
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                            "role_inference": _service_role_hint(source_port, destination_port),
                        },
                    )
                    item["packets"] += 1
                    item["bytes"] += frame_len
                    item["protocols"][dominant] += 1
                    if timestamp is not None:
                        item["first_seen"] = (
                            timestamp
                            if item["first_seen"] is None
                            else min(float(item["first_seen"]), timestamp)
                        )
                        item["last_seen"] = (
                            timestamp
                            if item["last_seen"] is None
                            else max(float(item["last_seen"]), timestamp)
                        )

                yield raw

        document = super().analyze_tsv(tapped(), source=source, progress=progress)

        normalized_identity = []
        ip_to_macs: defaultdict[str, set[str]] = defaultdict(set)
        for item in identity_links.values():
            ip_to_macs[str(item["ip"])].add(str(item["mac"]))
            normalized_identity.append(
                {
                    "ip": item["ip"],
                    "mac": item["mac"],
                    "confidence": item["confidence"],
                    "evidence": [
                        {"type": name, "count": count}
                        for name, count in item["evidence"].most_common()
                    ],
                    "first_seen": _iso(item["first_seen"]),
                    "last_seen": _iso(item["last_seen"]),
                }
            )
        normalized_identity.sort(
            key=lambda item: (
                _CONFIDENCE_RANK.get(str(item["confidence"]), 0),
                sum(entry["count"] for entry in item["evidence"]),
            ),
            reverse=True,
        )

        normalized_flows = []
        for item in flow_items.values():
            normalized_flows.append(
                {
                    "src_endpoint": item["src_endpoint"],
                    "dst_endpoint": item["dst_endpoint"],
                    "src_ip": item["src_ip"],
                    "dst_ip": item["dst_ip"],
                    "src_mac": item["src_mac"],
                    "dst_mac": item["dst_mac"],
                    "src_port": item["src_port"],
                    "dst_port": item["dst_port"],
                    "transport": item["transport"],
                    "packets": item["packets"],
                    "bytes": item["bytes"],
                    "protocols": [
                        {"name": name, "frames": count}
                        for name, count in item["protocols"].most_common(8)
                    ],
                    "first_seen": _iso(item["first_seen"]),
                    "last_seen": _iso(item["last_seen"]),
                    "direction": "observed",
                    "role_inference": item["role_inference"],
                    "provenance": "pcap",
                }
            )
        normalized_flows.sort(
            key=lambda item: (int(item["bytes"]), int(item["packets"])), reverse=True
        )

        endpoint_evidence = []
        for endpoint, roles in endpoint_roles.items():
            if roles["confirmed_responder"]:
                state = "confirmed_responder"
            elif roles["observed_sender"]:
                state = "observed_sender"
            elif roles["external_peer"]:
                state = "external_peer"
            elif roles["observed_peer"]:
                state = "observed_peer"
            else:
                state = "probed_target"
            endpoint_evidence.append(
                {
                    "endpoint": endpoint,
                    "state": state,
                    "evidence_counts": dict(roles),
                    "topology_default_visible": state
                    in {"confirmed_responder", "observed_sender"},
                }
            )
        endpoint_evidence.sort(
            key=lambda item: (
                item["state"] == "confirmed_responder",
                item["state"] == "observed_sender",
                sum(int(value) for value in item["evidence_counts"].values()),
            ),
            reverse=True,
        )

        interface = str(source.get("interface") or "")
        logical_vlan = None
        vlan_basis = None
        vlan_match = re.fullmatch(r"(?i)vlan(\d+)", interface)
        if vlan_match:
            logical_vlan = vlan_match.group(1)
            vlan_basis = "interface_name_hint"

        document["schema_version"] = 2
        document["evidence_model"] = {
            "version": 1,
            "principle": "observations_before_inference",
        }
        document["capture_context"] = {
            "interface": source.get("interface"),
            "filter": source.get("filter"),
            "logical_vlan_hint": logical_vlan,
            "logical_vlan_hint_basis": vlan_basis,
            "observed_vlan_tags": [
                {"vlan_id": vlan, "frames": count}
                for vlan, count in observed_vlan_tags.most_common()
            ],
            "vlan_tag_visibility": "observed" if observed_vlan_tags else "not_observed",
            "note": (
                "Логический VLAN точки захвата и 802.1Q tag в кадре — разные факты; "
                "отсутствие vlan.id не доказывает отсутствие VLAN."
            ),
        }
        document["identity_observations"] = {
            "links": normalized_identity[:1000],
            "ambiguous_ips": [
                {"ip": ip_value, "macs": sorted(mac_values)}
                for ip_value, mac_values in sorted(ip_to_macs.items())
                if len(mac_values) > 1
            ],
        }
        document["endpoint_evidence"] = endpoint_evidence[:2000]
        document["directional_flows"] = normalized_flows[:2000]
        document["observation_domain"] = {
            "private_ipv4_prefix_hints": [
                {"prefix": prefix, "frames": count, "confidence": "hint"}
                for prefix, count in private_prefixes.most_common(50)
            ],
            "prefix_hint_semantics": (
                "Группировка /24 используется только для сравнения observation domains; "
                "она не является определённой маской подсети."
            ),
        }

        arp = document.setdefault("arp", {})
        arp.update(
            {
                "request_count": arp_requests,
                "reply_count": arp_replies,
                "probed_targets": [
                    {"ip": ip_value, "requests": count, "confirmed_asset": False}
                    for ip_value, count in arp_probed_targets.most_common(1000)
                ],
                "confirmed_responders": [
                    {"ip": ip_value, "replies": count}
                    for ip_value, count in arp_confirmed_responders.most_common(500)
                ],
                "request_target_semantics": (
                    "ARP request target означает только запрошенный адрес и сам по себе "
                    "не подтверждает существование устройства."
                ),
            }
        )

        summary = document.setdefault("summary", {})
        summary["directional_flow_count"] = len(flow_items)
        summary["identity_link_count"] = len(identity_links)
        summary["arp_probed_target_count"] = len(arp_probed_targets)
        summary["arp_confirmed_responder_count"] = len(arp_confirmed_responders)

        document.setdefault("limitations", []).extend(
            [
                "IP<->MAC из Ethernet/IP source имеет contextual confidence: на маршрутизируемой точке захвата MAC может принадлежать immediate next-hop.",
                "Client/server role в directional flow пока является только низкоуверенной подсказкой по well-known port; handshake-based sessionization будет добавлена отдельным этапом.",
                "ARP request target не включается в подтверждённые устройства без дополнительного evidence.",
            ]
        )
        return document
