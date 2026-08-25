"""Advanced deterministic diagnostics for an already-retained PCAP.

This pass complements the base traffic analyzer with connection-oriented health
signals. It never generates network traffic; tshark reads the stored evidence
only. The output is intentionally phrased as observations/hints rather than
proven root causes because capture position and completeness materially affect
what can be inferred from a PCAP.
"""

from __future__ import annotations

from collections import Counter, defaultdict
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
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.syn_retransmission",
    "dns.qry.name",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.time",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.proto_ipv4",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
)


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return default


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truthy(value: str) -> bool:
    return bool(value) and value.strip().lower() not in {"0", "false", "no"}


def _ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _pair(source: str | None, destination: str | None) -> tuple[str, str] | None:
    if not source or not destination or source == destination:
        return None
    return tuple(sorted((source, destination)))


class AdvancedTrafficAnalyzer:
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
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        fd, output_name = tempfile.mkstemp(
            prefix="traffic-advanced-",
            suffix=".tsv",
            dir=pcap_path.parent,
        )
        import os

        os.close(fd)
        output_path = Path(output_name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(66, "Уточняем TCP, DNS, ARP и ICMP диагностику")
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
            for name in FIELDS:
                args.extend(["-e", name])
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
                code = "advanced_traffic_decode_failed"
                retryable = False
                if result.cancelled:
                    category = ErrorCategory.CANCELLED
                    code = "cancelled"
                elif result.timed_out:
                    category = ErrorCategory.TIMEOUT
                    code = "advanced_traffic_decode_timeout"
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
                            else "tshark could not perform advanced PCAP diagnostics"
                        ),
                        component="traffic_analysis",
                        retryable=retryable,
                        details={
                            "exit_code": result.exit_code,
                            "tool_error": result.error.code.value if result.error else None,
                        },
                    )
                )
            with output_path.open("r", encoding="utf-8", errors="replace") as stream:
                return self.analyze_tsv(stream, progress=progress)
        finally:
            output_path.unlink(missing_ok=True)

    def analyze_tsv(
        self,
        lines: Iterable[str],
        *,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        index = {name: position for position, name in enumerate(FIELDS)}
        first_ts: float | None = None
        last_ts: float | None = None
        frames = 0
        byte_count = 0

        tcp_streams: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "pair": None,
                "initial_syn": 0,
                "syn_ack": 0,
                "syn_retransmissions": 0,
                "rst": 0,
            }
        )
        pair_health: defaultdict[tuple[str, str], Counter[str]] = defaultdict(Counter)

        dns_times_ms: list[float] = []
        dns_slow_names: defaultdict[str, list[float]] = defaultdict(list)
        dns_error_names: Counter[str] = Counter()
        dns_error_clients: Counter[str] = Counter()

        arp_requests: Counter[str] = Counter()
        arp_replies: Counter[str] = Counter()

        icmp_types: Counter[str] = Counter()
        icmp_sources: Counter[str] = Counter()

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

            frames += 1
            byte_count += _int(field(columns, "frame.len"))
            timestamp = _float(field(columns, "frame.time_epoch"))
            if timestamp is not None:
                first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
                last_ts = timestamp if last_ts is None else max(last_ts, timestamp)

            source = _ip(field(columns, "ip.src")) or _ip(field(columns, "ipv6.src"))
            destination = _ip(field(columns, "ip.dst")) or _ip(field(columns, "ipv6.dst"))
            pair = _pair(source, destination)

            stream_id = field(columns, "tcp.stream")
            if stream_id:
                stream = tcp_streams[stream_id]
                if pair:
                    stream["pair"] = pair
                syn = _truthy(field(columns, "tcp.flags.syn"))
                ack = _truthy(field(columns, "tcp.flags.ack"))
                rst = _truthy(field(columns, "tcp.flags.reset"))
                if syn and not ack:
                    stream["initial_syn"] += 1
                if syn and ack:
                    stream["syn_ack"] += 1
                if _truthy(field(columns, "tcp.analysis.syn_retransmission")):
                    stream["syn_retransmissions"] += 1
                if rst:
                    stream["rst"] += 1

                if pair:
                    health = pair_health[pair]
                    health["tcp_packets"] += 1
                    if _truthy(field(columns, "tcp.analysis.retransmission")):
                        health["retransmissions"] += 1
                    if _truthy(field(columns, "tcp.analysis.duplicate_ack")):
                        health["duplicate_acks"] += 1
                    if _truthy(field(columns, "tcp.analysis.out_of_order")):
                        health["out_of_order"] += 1
                    if _truthy(field(columns, "tcp.analysis.zero_window")):
                        health["zero_window"] += 1
                    if rst:
                        health["resets"] += 1
                    if _truthy(field(columns, "tcp.analysis.syn_retransmission")):
                        health["syn_retransmissions"] += 1

            dns_response = _truthy(field(columns, "dns.flags.response"))
            dns_name = field(columns, "dns.qry.name").strip().lower().rstrip(".")
            if dns_response:
                dns_time = _float(field(columns, "dns.time"))
                if dns_time is not None and dns_time >= 0:
                    milliseconds = dns_time * 1000.0
                    dns_times_ms.append(milliseconds)
                    if dns_name:
                        dns_slow_names[dns_name].append(milliseconds)
                rcode = field(columns, "dns.flags.rcode")
                if rcode in {"2", "3"}:
                    if dns_name:
                        dns_error_names[dns_name] += 1
                    if destination:
                        dns_error_clients[destination] += 1

            arp_opcode = _int(field(columns, "arp.opcode"))
            arp_source = _ip(field(columns, "arp.src.proto_ipv4"))
            arp_target = _ip(field(columns, "arp.dst.proto_ipv4"))
            if arp_opcode == 1 and arp_target:
                arp_requests[arp_target] += 1
            elif arp_opcode == 2 and arp_source:
                arp_replies[arp_source] += 1

            icmp_type = field(columns, "icmp.type")
            icmp_code = field(columns, "icmp.code")
            icmpv6_type = field(columns, "icmpv6.type")
            icmpv6_code = field(columns, "icmpv6.code")
            if icmp_type:
                key = f"icmp:{icmp_type}/{icmp_code or '0'}"
                icmp_types[key] += 1
                if source:
                    icmp_sources[source] += 1
            elif icmpv6_type:
                key = f"icmpv6:{icmpv6_type}/{icmpv6_code or '0'}"
                icmp_types[key] += 1
                if source:
                    icmp_sources[source] += 1

            if progress and row_number % 50_000 == 0:
                progress(72, f"Расширенная диагностика: {row_number:,} кадров")

        duration = max(0.0, (last_ts or 0.0) - (first_ts or last_ts or 0.0))
        rates = {
            "frames_per_second": round(frames / duration, 2) if duration > 0 else 0.0,
            "bytes_per_second": round(byte_count / duration, 2) if duration > 0 else 0.0,
            "bits_per_second": round(byte_count * 8.0 / duration, 2) if duration > 0 else 0.0,
            "megabits_per_second": round(byte_count * 8.0 / duration / 1_000_000.0, 3)
            if duration > 0
            else 0.0,
        }

        attempted_streams = 0
        syn_ack_observed = 0
        no_syn_ack = 0
        syn_retransmission_streams = 0
        reset_streams = 0
        failed_pairs: Counter[tuple[str, str]] = Counter()
        for stream in tcp_streams.values():
            if stream["initial_syn"]:
                attempted_streams += 1
                if stream["syn_ack"]:
                    syn_ack_observed += 1
                else:
                    no_syn_ack += 1
                    if stream["pair"]:
                        failed_pairs[stream["pair"]] += 1
            if stream["syn_retransmissions"]:
                syn_retransmission_streams += 1
            if stream["rst"]:
                reset_streams += 1

        pair_rows: list[dict[str, Any]] = []
        for pair, counters in pair_health.items():
            issue_count = sum(
                counters[name]
                for name in (
                    "retransmissions",
                    "duplicate_acks",
                    "out_of_order",
                    "zero_window",
                    "resets",
                    "syn_retransmissions",
                )
            )
            if not issue_count:
                continue
            pair_rows.append(
                {
                    "endpoint_a": pair[0],
                    "endpoint_b": pair[1],
                    "tcp_packets": counters["tcp_packets"],
                    "issue_count": issue_count,
                    "retransmissions": counters["retransmissions"],
                    "duplicate_acks": counters["duplicate_acks"],
                    "out_of_order": counters["out_of_order"],
                    "zero_window": counters["zero_window"],
                    "resets": counters["resets"],
                    "syn_retransmissions": counters["syn_retransmissions"],
                }
            )
        pair_rows.sort(key=lambda item: (item["issue_count"], item["tcp_packets"]), reverse=True)

        p50 = _percentile(dns_times_ms, 0.50)
        p95 = _percentile(dns_times_ms, 0.95)
        dns_max = max(dns_times_ms) if dns_times_ms else None
        slow_names = sorted(
            (
                {
                    "name": name,
                    "samples": len(values),
                    "average_ms": round(sum(values) / len(values), 2),
                    "max_ms": round(max(values), 2),
                }
                for name, values in dns_slow_names.items()
                if values
            ),
            key=lambda item: (item["max_ms"], item["average_ms"]),
            reverse=True,
        )

        unanswered = [
            {"ip": address, "requests": count}
            for address, count in arp_requests.most_common()
            if arp_replies.get(address, 0) == 0
        ]

        icmp_error_count = 0
        for name, count in icmp_types.items():
            if name.startswith("icmp:"):
                type_number = _int(name.split(":", 1)[1].split("/", 1)[0])
                if type_number in {3, 4, 5, 11, 12}:
                    icmp_error_count += count
            else:
                type_number = _int(name.split(":", 1)[1].split("/", 1)[0])
                if type_number in {1, 2, 3, 4}:
                    icmp_error_count += count

        observations: list[dict[str, str]] = []
        syn_retransmissions = sum(
            item["syn_retransmissions"] for item in pair_rows
        )
        if attempted_streams >= 5 and no_syn_ack >= 3 and no_syn_ack / attempted_streams >= 0.20:
            observations.append(
                {
                    "severity": "warning",
                    "category": "tcp",
                    "title": "Часть TCP-подключений не получила наблюдаемого SYN/ACK",
                    "fact": (
                        f"Из {attempted_streams} TCP-потоков, где начало соединения попало в PCAP, "
                        f"для {no_syn_ack} не наблюдался SYN/ACK."
                    ),
                    "meaning": (
                        "Это бывает при недоступном сервисе, фильтрации, потерях или асимметричной видимости. "
                        "Обрезанный/односторонний захват также может давать такой симптом."
                    ),
                    "check": (
                        "Проверьте пары с незавершённым handshake, состояние firewall/ACL и повторите захват "
                        "в точке, где видны оба направления трафика."
                    ),
                }
            )
        if syn_retransmissions >= 3:
            observations.append(
                {
                    "severity": "warning",
                    "category": "tcp",
                    "title": "Наблюдались повторные TCP SYN",
                    "fact": f"Кадров, отмеченных tshark как SYN retransmission: {syn_retransmissions}.",
                    "meaning": "Повторные SYN могут сопровождать потери, фильтрацию или отсутствие ответа от целевого сервиса.",
                    "check": "Посмотрите проблемные TCP-пары ниже и проверьте доступность целевого порта и сетевой путь.",
                }
            )
        if len(dns_times_ms) >= 5 and p95 is not None and p95 >= 500.0:
            observations.append(
                {
                    "severity": "warning",
                    "category": "dns",
                    "title": "Повышенное время ответа DNS",
                    "fact": f"DNS latency p95: {p95:.1f} мс по {len(dns_times_ms)} ответам; максимум {dns_max:.1f} мс.",
                    "meaning": "Высокая DNS-задержка может замедлять приложения даже при исправном TCP-трафике.",
                    "check": "Проверьте самые медленные DNS-имена, доступность резолвера и путь до DNS-сервера.",
                }
            )
        noisy_unanswered = [item for item in unanswered if item["requests"] >= 3]
        if noisy_unanswered:
            top = ", ".join(f"{item['ip']} ({item['requests']})" for item in noisy_unanswered[:5])
            observations.append(
                {
                    "severity": "info",
                    "category": "arp",
                    "title": "Повторные ARP-запросы без наблюдаемого ответа",
                    "fact": f"Цели: {top}.",
                    "meaning": "Узел мог быть выключен/недоступен, либо ответ не попал в точку или интервал захвата.",
                    "check": "Проверьте существование этих адресов, VLAN/L2-доступность и повторите захват при необходимости.",
                }
            )
        if icmp_error_count >= 3:
            observations.append(
                {
                    "severity": "info",
                    "category": "icmp",
                    "title": "Наблюдались диагностические ICMP-сообщения",
                    "fact": f"ICMP/ICMPv6 сообщений диагностических типов: {icmp_error_count}.",
                    "meaning": "Они могут указывать на недоступность адреса/порта, MTU или истечение TTL, но часть таких сообщений штатна.",
                    "check": "Сопоставьте типы ICMP и источники ниже с конкретными соединениями и маршрутами.",
                }
            )

        return {
            "rates": rates,
            "tcp_connections": {
                "streams_seen": len(tcp_streams),
                "attempted_streams": attempted_streams,
                "syn_ack_observed": syn_ack_observed,
                "no_syn_ack_observed": no_syn_ack,
                "syn_retransmission_streams": syn_retransmission_streams,
                "reset_streams": reset_streams,
                "top_problem_pairs": pair_rows[:30],
                "top_no_syn_ack_pairs": [
                    {
                        "endpoint_a": pair[0],
                        "endpoint_b": pair[1],
                        "streams": count,
                    }
                    for pair, count in failed_pairs.most_common(20)
                ],
            },
            "dns_latency": {
                "samples": len(dns_times_ms),
                "average_ms": round(sum(dns_times_ms) / len(dns_times_ms), 2)
                if dns_times_ms
                else None,
                "p50_ms": round(p50, 2) if p50 is not None else None,
                "p95_ms": round(p95, 2) if p95 is not None else None,
                "max_ms": round(dns_max, 2) if dns_max is not None else None,
                "slow_names": slow_names[:20],
                "top_error_names": [
                    {"name": name, "count": count}
                    for name, count in dns_error_names.most_common(20)
                ],
                "top_error_clients": [
                    {"endpoint": endpoint, "count": count}
                    for endpoint, count in dns_error_clients.most_common(20)
                ],
            },
            "arp_diagnostics": {
                "request_count": sum(arp_requests.values()),
                "reply_count": sum(arp_replies.values()),
                "unanswered_targets": unanswered[:50],
            },
            "icmp": {
                "diagnostic_error_count": icmp_error_count,
                "types": [
                    {"type": name, "count": count}
                    for name, count in icmp_types.most_common(30)
                ],
                "top_sources": [
                    {"endpoint": endpoint, "count": count}
                    for endpoint, count in icmp_sources.most_common(20)
                ],
            },
            "observations": observations,
        }


def merge_advanced(document: dict[str, Any], advanced: dict[str, Any]) -> dict[str, Any]:
    """Merge additive M10.3 diagnostics into traffic-analysis v1."""
    document["rates"] = advanced.get("rates") or {}
    document["tcp_connections"] = advanced.get("tcp_connections") or {}
    document["dns_latency"] = advanced.get("dns_latency") or {}
    document["arp_diagnostics"] = advanced.get("arp_diagnostics") or {}
    document["icmp"] = advanced.get("icmp") or {}
    existing = list(document.get("observations") or [])
    existing.extend(advanced.get("observations") or [])
    document["observations"] = existing
    return document
