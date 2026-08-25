"""Deterministic, bounded analysis of an already-retained PCAP.

The analyzer deliberately does not perform new network activity. tshark decodes a
controlled set of fields into a temporary TSV file and Python aggregates that
stream. The temporary decode is not evidence and is removed after processing.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable

from config.settings import Settings, get_settings
from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError
from providers.tools import CancellationToken, ToolCommand, ToolRunner


FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "tcp.analysis.zero_window",
    "tcp.flags.reset",
    "dns.qry.name",
    "dns.flags.rcode",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.proto_ipv4",
    "arp.dst.hw_mac",
    "vlan.id",
)

# Most-specific first. This is used only to put each frame into one readable
# protocol bucket; the complete protocol stack is still retained per edge.
DOMINANT_PROTOCOLS: tuple[str, ...] = (
    "quic",
    "http3",
    "http2",
    "tls",
    "ssh",
    "telnet",
    "ftp",
    "smb2",
    "smb",
    "ldap",
    "snmp",
    "http",
    "dns",
    "mdns",
    "llmnr",
    "nbns",
    "dhcpv6",
    "dhcp",
    "bootp",
    "ssdp",
    "ntp",
    "icmpv6",
    "icmp",
    "arp",
    "tcp",
    "udp",
    "ipv6",
    "ip",
)

LEGACY_PROTOCOL_NOTES: dict[str, tuple[str, str, str]] = {
    "telnet": (
        "Обнаружен Telnet",
        "Telnet обычно передаёт данные и учётные данные без шифрования.",
        "Проверьте назначение соединений и возможность замены Telnet на SSH.",
    ),
    "ftp": (
        "Обнаружен FTP",
        "Обычный FTP не защищает управляющий канал и учётные данные шифрованием.",
        "Проверьте, требуется ли FTP, и рассмотрите SFTP/FTPS там, где это применимо.",
    ),
    "http": (
        "Наблюдался обычный HTTP",
        "Часть HTTP-трафика может передаваться без транспортного шифрования.",
        "Проверьте назначение HTTP-соединений и необходимость HTTPS для чувствительных данных.",
    ),
    "llmnr": (
        "Наблюдался LLMNR",
        "LLMNR расширяет поверхность локального разрешения имён и часто не нужен в управляемых сетях.",
        "Проверьте, требуется ли LLMNR на этих узлах и можно ли использовать управляемый DNS.",
    ),
    "nbns": (
        "Наблюдался NBNS/NetBIOS Name Service",
        "NBNS является устаревшим локальным механизмом разрешения имён и создаёт дополнительный broadcast-трафик.",
        "Проверьте зависимость старых систем от NetBIOS и возможность отключения NBNS.",
    ),
}


def _number(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truthy_field(value: str) -> bool:
    if value == "":
        return False
    return value.lower() not in {"0", "false", "no"}


def _safe_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _endpoint(ip_value: str | None, mac_value: str | None) -> tuple[str | None, str | None]:
    if ip_value:
        return ip_value, "ip"
    if mac_value:
        return mac_value.lower(), "mac"
    return None, None


def _is_broadcast(destination_ip: str | None, destination_mac: str | None) -> bool:
    if destination_mac and destination_mac.lower() == "ff:ff:ff:ff:ff:ff":
        return True
    return destination_ip == "255.255.255.255"


def _is_multicast(destination_ip: str | None, destination_mac: str | None) -> bool:
    if destination_ip:
        try:
            if ipaddress.ip_address(destination_ip).is_multicast:
                return True
        except ValueError:
            pass
    if destination_mac:
        lowered = destination_mac.lower()
        return lowered.startswith("01:00:5e:") or lowered.startswith("33:33:")
    return False


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class TrafficAnalyzer:
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()

    def analyze(
        self,
        pcap_path: Path,
        *,
        source: dict[str, Any],
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        if not pcap_path.is_file():
            raise JobExecutionError(
                JobError(
                    code="pcap_not_found",
                    category=ErrorCategory.VALIDATION,
                    message="Stored PCAP file is missing",
                    component="traffic_analysis",
                )
            )

        fd, output_name = tempfile.mkstemp(
            prefix="traffic-analysis-",
            suffix=".tsv",
            dir=pcap_path.parent,
        )
        import os

        os.close(fd)
        output_path = Path(output_name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(10, "tshark читает сохранённый PCAP")
            args = [
                "-r",
                str(pcap_path),
                "-n",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=f",
                "-E",
                "header=n",
            ]
            for field in FIELDS:
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
                code = "traffic_decode_failed"
                retryable = False
                if result.cancelled:
                    category = ErrorCategory.CANCELLED
                    code = "cancelled"
                elif result.timed_out:
                    category = ErrorCategory.TIMEOUT
                    code = "traffic_decode_timeout"
                    retryable = True
                elif result.error and result.error.code.value == "missing_binary":
                    category = ErrorCategory.TOOL_MISSING
                    code = "tshark_unavailable"
                raise JobExecutionError(
                    JobError(
                        code=code,
                        category=category,
                        message=(
                            result.error.message
                            if result.error
                            else "tshark could not decode the stored PCAP"
                        ),
                        component="traffic_analysis",
                        retryable=retryable,
                        details={
                            "exit_code": result.exit_code,
                            "tool_error": result.error.code.value if result.error else None,
                        },
                    )
                )

            if progress:
                progress(45, "Агрегируем узлы, протоколы и соединения")
            with output_path.open("r", encoding="utf-8", errors="replace") as stream:
                document = self.analyze_tsv(stream, source=source, progress=progress)
            return document
        finally:
            output_path.unlink(missing_ok=True)

    def analyze_tsv(
        self,
        lines: Iterable[str],
        *,
        source: dict[str, Any],
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        index = {name: position for position, name in enumerate(FIELDS)}
        total_frames = 0
        total_bytes = 0
        first_ts: float | None = None
        last_ts: float | None = None
        macs: set[str] = set()
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        vlans: set[str] = set()
        protocol_counts: Counter[str] = Counter()
        all_protocol_counts: Counter[str] = Counter()

        endpoint_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "kind": "unknown",
                "tx_packets": 0,
                "rx_packets": 0,
                "tx_bytes": 0,
                "rx_bytes": 0,
            }
        )
        conversations: dict[tuple[str, str], dict[str, Any]] = {}

        tcp = Counter()
        dns_names: Counter[str] = Counter()
        dns_rcodes: Counter[str] = Counter()
        dns_queries_by_source: Counter[str] = Counter()
        arp_bindings: defaultdict[str, set[str]] = defaultdict(set)
        gratuitous_arp = 0
        dhcp_servers: Counter[str] = Counter()
        broadcast_frames = 0
        broadcast_bytes = 0
        multicast_frames = 0
        multicast_bytes = 0
        broadcast_sources: Counter[str] = Counter()
        multicast_sources: Counter[str] = Counter()

        def field(columns: list[str], name: str) -> str:
            position = index[name]
            return columns[position].strip() if position < len(columns) else ""

        for row_number, raw in enumerate(lines, start=1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) < len(FIELDS):
                columns.extend([""] * (len(FIELDS) - len(columns)))

            total_frames += 1
            frame_len = _number(field(columns, "frame.len"))
            total_bytes += frame_len
            timestamp = _float(field(columns, "frame.time_epoch"))
            if timestamp is not None:
                first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
                last_ts = timestamp if last_ts is None else max(last_ts, timestamp)

            source_mac = field(columns, "eth.src").lower() or None
            destination_mac = field(columns, "eth.dst").lower() or None
            source_ip = _safe_ip(field(columns, "ip.src")) or _safe_ip(field(columns, "ipv6.src"))
            destination_ip = _safe_ip(field(columns, "ip.dst")) or _safe_ip(field(columns, "ipv6.dst"))

            for mac in (source_mac, destination_mac):
                if mac:
                    macs.add(mac)
            for address in (source_ip, destination_ip):
                if not address:
                    continue
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                (ipv4 if parsed.version == 4 else ipv6).add(address)
            vlan = field(columns, "vlan.id")
            if vlan:
                vlans.add(vlan)

            protocols = [
                item.strip().lower()
                for item in field(columns, "frame.protocols").split(":")
                if item.strip()
            ]
            for protocol in set(protocols):
                all_protocol_counts[protocol] += 1
            dominant = next(
                (name for name in DOMINANT_PROTOCOLS if name in protocols),
                protocols[-1] if protocols else "other",
            )
            protocol_counts[dominant] += 1

            src_endpoint, src_kind = _endpoint(source_ip, source_mac)
            dst_endpoint, dst_kind = _endpoint(destination_ip, destination_mac)
            if src_endpoint:
                current = endpoint_stats[src_endpoint]
                current["kind"] = src_kind or current["kind"]
                current["tx_packets"] += 1
                current["tx_bytes"] += frame_len
            if dst_endpoint:
                current = endpoint_stats[dst_endpoint]
                current["kind"] = dst_kind or current["kind"]
                current["rx_packets"] += 1
                current["rx_bytes"] += frame_len

            tcp_src = field(columns, "tcp.srcport")
            tcp_dst = field(columns, "tcp.dstport")
            udp_src = field(columns, "udp.srcport")
            udp_dst = field(columns, "udp.dstport")
            transport = "tcp" if tcp_src or tcp_dst else "udp" if udp_src or udp_dst else ""
            source_port = tcp_src or udp_src
            destination_port = tcp_dst or udp_dst

            if src_endpoint and dst_endpoint and src_endpoint != dst_endpoint:
                a, b = sorted((src_endpoint, dst_endpoint))
                key = (a, b)
                item = conversations.setdefault(
                    key,
                    {
                        "endpoint_a": a,
                        "endpoint_b": b,
                        "packets_a_to_b": 0,
                        "packets_b_to_a": 0,
                        "bytes_a_to_b": 0,
                        "bytes_b_to_a": 0,
                        "protocols": Counter(),
                        "ports": Counter(),
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                    },
                )
                if src_endpoint == a:
                    item["packets_a_to_b"] += 1
                    item["bytes_a_to_b"] += frame_len
                else:
                    item["packets_b_to_a"] += 1
                    item["bytes_b_to_a"] += frame_len
                item["protocols"][dominant] += 1
                if transport and destination_port:
                    item["ports"][f"{transport}/{destination_port}"] += 1
                if timestamp is not None:
                    item["first_seen"] = (
                        timestamp
                        if item["first_seen"] is None
                        else min(item["first_seen"], timestamp)
                    )
                    item["last_seen"] = (
                        timestamp
                        if item["last_seen"] is None
                        else max(item["last_seen"], timestamp)
                    )

            if "tcp" in protocols:
                tcp["packets"] += 1
                if _truthy_field(field(columns, "tcp.analysis.retransmission")):
                    tcp["retransmissions"] += 1
                if _truthy_field(field(columns, "tcp.analysis.duplicate_ack")):
                    tcp["duplicate_acks"] += 1
                if _truthy_field(field(columns, "tcp.analysis.out_of_order")):
                    tcp["out_of_order"] += 1
                if _truthy_field(field(columns, "tcp.analysis.lost_segment")):
                    tcp["lost_segments"] += 1
                if _truthy_field(field(columns, "tcp.analysis.zero_window")):
                    tcp["zero_window"] += 1
                if _truthy_field(field(columns, "tcp.flags.reset")):
                    tcp["resets"] += 1

            dns_name = field(columns, "dns.qry.name").strip().lower().rstrip(".")
            if dns_name:
                dns_names[dns_name] += 1
                if source_ip:
                    dns_queries_by_source[source_ip] += 1
            rcode = field(columns, "dns.flags.rcode")
            if rcode:
                dns_rcodes[rcode] += 1

            arp_source_ip = _safe_ip(field(columns, "arp.src.proto_ipv4"))
            arp_source_mac = field(columns, "arp.src.hw_mac").lower()
            arp_destination_ip = _safe_ip(field(columns, "arp.dst.proto_ipv4"))
            if arp_source_ip and arp_source_mac:
                arp_bindings[arp_source_ip].add(arp_source_mac)
            if arp_source_ip and arp_destination_ip and arp_source_ip == arp_destination_ip:
                gratuitous_arp += 1

            if udp_src == "67" and source_ip:
                dhcp_servers[source_ip] += 1

            is_broadcast = _is_broadcast(destination_ip, destination_mac)
            is_multicast = _is_multicast(destination_ip, destination_mac)
            source_label = src_endpoint or source_mac or "unknown"
            if is_broadcast:
                broadcast_frames += 1
                broadcast_bytes += frame_len
                broadcast_sources[source_label] += 1
            elif is_multicast:
                multicast_frames += 1
                multicast_bytes += frame_len
                multicast_sources[source_label] += 1

            if progress and row_number % 50_000 == 0:
                progress(60, f"Обработано {row_number:,} кадров")

        duration = max(0.0, (last_ts or 0.0) - (first_ts or last_ts or 0.0))
        talkers = []
        for endpoint, stats in endpoint_stats.items():
            total_endpoint_packets = stats["tx_packets"] + stats["rx_packets"]
            total_endpoint_bytes = stats["tx_bytes"] + stats["rx_bytes"]
            talkers.append(
                {
                    "endpoint": endpoint,
                    "kind": stats["kind"],
                    **stats,
                    "packets": total_endpoint_packets,
                    "bytes": total_endpoint_bytes,
                }
            )
        talkers.sort(key=lambda item: (item["bytes"], item["packets"]), reverse=True)

        normalized_conversations: list[dict[str, Any]] = []
        for item in conversations.values():
            packets = item["packets_a_to_b"] + item["packets_b_to_a"]
            byte_count = item["bytes_a_to_b"] + item["bytes_b_to_a"]
            normalized_conversations.append(
                {
                    "endpoint_a": item["endpoint_a"],
                    "endpoint_b": item["endpoint_b"],
                    "packets": packets,
                    "bytes": byte_count,
                    "packets_a_to_b": item["packets_a_to_b"],
                    "packets_b_to_a": item["packets_b_to_a"],
                    "bytes_a_to_b": item["bytes_a_to_b"],
                    "bytes_b_to_a": item["bytes_b_to_a"],
                    "protocols": [
                        {"name": name, "frames": count}
                        for name, count in item["protocols"].most_common(8)
                    ],
                    "ports": [
                        {"port": name, "frames": count}
                        for name, count in item["ports"].most_common(12)
                    ],
                    "first_seen": _iso(item["first_seen"]),
                    "last_seen": _iso(item["last_seen"]),
                    "provenance": "pcap",
                    "confidence": "observed",
                }
            )
        normalized_conversations.sort(key=lambda item: (item["bytes"], item["packets"]), reverse=True)

        protocol_distribution = [
            {
                "name": name,
                "frames": count,
                "percent": round((count * 100.0 / total_frames), 2) if total_frames else 0.0,
            }
            for name, count in protocol_counts.most_common(30)
        ]

        arp_items = [
            {
                "ip": address,
                "macs": sorted(macs_for_ip),
                "conflict": len(macs_for_ip) > 1,
            }
            for address, macs_for_ip in sorted(arp_bindings.items())
        ]
        arp_conflicts = [item for item in arp_items if item["conflict"]]

        tcp_packets = tcp["packets"]
        retransmission_rate = (
            round(tcp["retransmissions"] * 100.0 / tcp_packets, 2)
            if tcp_packets
            else 0.0
        )
        dns_total_responses = sum(dns_rcodes.values())
        nxdomain = dns_rcodes.get("3", 0)
        servfail = dns_rcodes.get("2", 0)
        broadcast_percent = round(broadcast_frames * 100.0 / total_frames, 2) if total_frames else 0.0
        multicast_percent = round(multicast_frames * 100.0 / total_frames, 2) if total_frames else 0.0

        observations: list[dict[str, str]] = []
        if tcp_packets >= 20 and retransmission_rate >= 2.0:
            observations.append(
                {
                    "severity": "warning",
                    "category": "tcp",
                    "title": "Повышенная доля TCP retransmission",
                    "fact": f"Зафиксировано {tcp['retransmissions']} retransmission из {tcp_packets} TCP-пакетов ({retransmission_rate}%).",
                    "meaning": "Это может быть признаком потерь, перегрузки, нестабильного канала или особенностей точки захвата.",
                    "check": "Проверьте наиболее активные TCP-пары, ошибки интерфейсов и загрузку пути; подтвердите симптом захватом ближе к проблемному узлу.",
                }
            )
        if tcp["zero_window"]:
            observations.append(
                {
                    "severity": "warning",
                    "category": "tcp",
                    "title": "Наблюдались TCP Zero Window",
                    "fact": f"Кадров с TCP Zero Window: {tcp['zero_window']}.",
                    "meaning": "Получатель временно сообщал об отсутствии свободного TCP receive window; это может указывать на задержку обработки данных приложением или ресурсное ограничение.",
                    "check": "Проверьте, между какими узлами возникает Zero Window, и состояние приложения/CPU/памяти принимающей стороны.",
                }
            )
        if dns_total_responses >= 10 and (nxdomain + servfail) / dns_total_responses >= 0.10:
            observations.append(
                {
                    "severity": "warning",
                    "category": "dns",
                    "title": "Заметная доля ошибок DNS",
                    "fact": f"NXDOMAIN: {nxdomain}, SERVFAIL: {servfail}, DNS-ответов с кодом результата: {dns_total_responses}.",
                    "meaning": "Частые отрицательные ответы могут быть нормальны для части приложений, но также возникают при ошибках имён, DNS-конфигурации или недоступных зонах.",
                    "check": "Проверьте самые частые имена и узлы-источники запросов, затем сопоставьте их с настройками DNS и приложений.",
                }
            )
        for conflict in arp_conflicts:
            observations.append(
                {
                    "severity": "warning",
                    "category": "arp",
                    "title": f"Один IPv4 наблюдался с несколькими MAC: {conflict['ip']}",
                    "fact": f"MAC-адреса: {', '.join(conflict['macs'])}.",
                    "meaning": "Это может быть IP-конфликтом, HA/VRRP-сценарием, сменой устройства или иным штатным изменением. Один PCAP не доказывает ARP spoofing.",
                    "check": "Сопоставьте MAC с сетевым оборудованием/виртуализацией и проверьте ARP/FDB таблицы в момент события.",
                }
            )
        if total_frames >= 100 and broadcast_percent >= 20.0:
            observations.append(
                {
                    "severity": "warning",
                    "category": "broadcast",
                    "title": "Высокая доля broadcast-трафика в захвате",
                    "fact": f"Broadcast: {broadcast_frames} кадров ({broadcast_percent}%).",
                    "meaning": "Высокая доля broadcast может быть признаком шумного сегмента, широкого L2-домена или конкретного источника, но зависит от точки захвата и фильтра.",
                    "check": "Проверьте top broadcast sources и типы протоколов; при необходимости повторите захват без ограничивающего BPF-фильтра.",
                }
            )
        for protocol, (title, meaning, check) in LEGACY_PROTOCOL_NOTES.items():
            hits = all_protocol_counts.get(protocol, 0)
            if hits:
                observations.append(
                    {
                        "severity": "info" if protocol == "http" else "warning",
                        "category": "security",
                        "title": title,
                        "fact": f"Кадров, где присутствует протокол {protocol}: {hits}.",
                        "meaning": meaning,
                        "check": check,
                    }
                )

        return {
            "schema": "traffic-analysis",
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": dict(source),
            "summary": {
                "frame_count": total_frames,
                "byte_count": total_bytes,
                "first_seen": _iso(first_ts),
                "last_seen": _iso(last_ts),
                "duration_seconds": round(duration, 3),
                "unique_macs": len(macs),
                "unique_ipv4": len(ipv4),
                "unique_ipv6": len(ipv6),
                "unique_endpoints": len(endpoint_stats),
                "conversation_count": len(normalized_conversations),
                "vlan_ids": sorted(vlans, key=lambda value: _number(value)),
            },
            "protocol_distribution": protocol_distribution,
            "top_talkers": talkers[:30],
            "conversations": normalized_conversations[:200],
            "communications_graph": {
                "schema": "communications-graph",
                "schema_version": 1,
                "nodes": [
                    {
                        "id": item["endpoint"],
                        "kind": item["kind"],
                        "packets": item["packets"],
                        "bytes": item["bytes"],
                    }
                    for item in talkers
                ],
                "edges": normalized_conversations[:500],
            },
            "tcp": {
                "packets": tcp_packets,
                "retransmissions": tcp["retransmissions"],
                "retransmission_percent": retransmission_rate,
                "duplicate_acks": tcp["duplicate_acks"],
                "out_of_order": tcp["out_of_order"],
                "lost_segments": tcp["lost_segments"],
                "zero_window": tcp["zero_window"],
                "resets": tcp["resets"],
            },
            "dns": {
                "query_count": sum(dns_names.values()),
                "top_names": [
                    {"name": name, "count": count}
                    for name, count in dns_names.most_common(30)
                ],
                "response_codes": dict(dns_rcodes),
                "nxdomain": nxdomain,
                "servfail": servfail,
                "top_sources": [
                    {"endpoint": name, "count": count}
                    for name, count in dns_queries_by_source.most_common(20)
                ],
            },
            "arp": {
                "bindings": arp_items[:500],
                "conflict_count": len(arp_conflicts),
                "gratuitous_arp": gratuitous_arp,
            },
            "dhcp": {
                "server_hints": [
                    {"endpoint": name, "frames": count}
                    for name, count in dhcp_servers.most_common(20)
                ]
            },
            "broadcast_multicast": {
                "broadcast_frames": broadcast_frames,
                "broadcast_bytes": broadcast_bytes,
                "broadcast_percent": broadcast_percent,
                "multicast_frames": multicast_frames,
                "multicast_bytes": multicast_bytes,
                "multicast_percent": multicast_percent,
                "top_broadcast_sources": [
                    {"endpoint": name, "frames": count}
                    for name, count in broadcast_sources.most_common(20)
                ],
                "top_multicast_sources": [
                    {"endpoint": name, "frames": count}
                    for name, count in multicast_sources.most_common(20)
                ],
            },
            "observations": observations,
            "limitations": [
                "Выводы относятся только к трафику, попавшему в этот PCAP и видимому в точке захвата.",
                "Promiscuous mode не заставляет коммутатор копировать чужой unicast-трафик; для полной видимости могут требоваться SPAN/mirror/TAP.",
                "Зашифрованный payload не расшифровывается; анализ использует доступные метаданные и протокольные признаки.",
                "Сетевой симптом не считается доказанной первопричиной без дополнительной проверки.",
            ],
        }
