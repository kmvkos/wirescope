"""Portable protocol-level intelligence for a retained PCAP.

This pass reads only the already-retained packet capture.  It intentionally uses
metadata exposed by tshark and never decrypts TLS payloads or exports application
content.  Wireshark field availability differs between distro versions, so the
analyzer first probes ``tshark -G fields`` and requests only supported fields.
Missing protocol-specific fields degrade one section instead of failing the whole
traffic analysis.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable

from config.settings import Settings, get_settings
from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError
from providers.tools import CancellationToken, ToolCommand, ToolRunner


FIELD_CANDIDATES: tuple[str, ...] = (
    # Common envelope.
    "frame.number",
    "frame.protocols",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    # TLS metadata.
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "tls.record.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str",
    # HTTP/1.x metadata.  Do not retain URI/body/cookie fields here.
    "http.host",
    "http.request.method",
    "http.response.code",
    # QUIC metadata.
    "quic.version",
    "quic.long.packet_type",
    # SMB2/3 metadata.
    "smb2.cmd",
    "smb2.nt_status",
    # Classic SMB fallback.
    "smb.cmd",
    "smb.nt_status",
    # DNS metadata.
    "dns.qry.name",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.a",
    "dns.aaaa",
    # DHCP/BOOTP — aliases differ by Wireshark generation.
    "dhcp.id",
    "bootp.id",
    "dhcp.option.dhcp",
    "bootp.option.dhcp",
    "dhcp.option.hostname",
    "bootp.option.hostname",
    "dhcp.option.dhcp_server_id",
    "bootp.option.dhcp_server_id",
    "dhcp.ip.your",
    "bootp.ip.your",
)

CORE_FIELDS: tuple[str, ...] = (
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
)

_TLS_VERSIONS = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
}

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

_SMB2_COMMANDS = {
    "0": "NEGOTIATE",
    "1": "SESSION_SETUP",
    "2": "LOGOFF",
    "3": "TREE_CONNECT",
    "4": "TREE_DISCONNECT",
    "5": "CREATE",
    "6": "CLOSE",
    "7": "FLUSH",
    "8": "READ",
    "9": "WRITE",
    "10": "LOCK",
    "11": "IOCTL",
    "12": "CANCEL",
    "13": "ECHO",
    "14": "QUERY_DIRECTORY",
    "15": "CHANGE_NOTIFY",
    "16": "QUERY_INFO",
    "17": "SET_INFO",
    "18": "OPLOCK_BREAK",
}


def _safe_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _truthy(value: str) -> bool:
    return value.strip().lower() not in {"", "0", "false", "no"}


def _pair(a: str | None, b: str | None) -> tuple[str, str] | None:
    if not a or not b or a == b:
        return None
    return tuple(sorted((a, b)))


def _normalize_tls_version(value: str) -> str | None:
    raw = value.strip().lower()
    if not raw:
        return None
    return _TLS_VERSIONS.get(raw, value.strip())


def _dhcp_type(value: str) -> str | None:
    raw = value.strip().upper()
    if not raw:
        return None
    if raw in _DHCP_TYPES.values():
        return raw
    # tshark can render an enum as "1 (DHCP Discover)" on some versions.
    token = raw.split()[0].strip("(),")
    if token in _DHCP_TYPES:
        return _DHCP_TYPES[token]
    for label in _DHCP_TYPES.values():
        if label in raw:
            return label
    return raw


def _smb_command(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    normalized = raw.lower()
    if normalized.startswith("0x"):
        try:
            normalized = str(int(normalized, 16))
        except ValueError:
            pass
    return _SMB2_COMMANDS.get(normalized, raw)


def _status_is_error(value: str) -> bool:
    raw = value.strip().lower()
    if not raw:
        return False
    return raw not in {
        "0",
        "0x00000000",
        "status_success",
        "success",
    }


def _counter_rows(counter: Counter[str], *, key: str, limit: int = 20) -> list[dict[str, Any]]:
    return [{key: name, "count": count} for name, count in counter.most_common(limit)]


def _pair_rows(counter: Counter[tuple[str, str]], limit: int = 20) -> list[dict[str, Any]]:
    return [
        {"endpoint_a": pair[0], "endpoint_b": pair[1], "frames": count}
        for pair, count in counter.most_common(limit)
    ]


class ProtocolIntelligenceAnalyzer:
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()

    def _supported_fields(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None,
    ) -> set[str]:
        fd, name = tempfile.mkstemp(prefix="tshark-fields-", suffix=".txt", dir=pcap_path.parent)
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
                        code="protocol_field_probe_failed",
                        category=category,
                        message=(result.error.message if result.error else "tshark field probe failed"),
                        component="traffic_analysis",
                        details={"exit_code": result.exit_code},
                    )
                )
            supported: set[str] = set()
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for raw in stream:
                    columns = raw.rstrip("\r\n").split("\t")
                    # tshark -G fields format: F, description, field abbreviation, ...
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
            progress(73, "Определяем доступные поля протоколов tshark")
        supported = self._supported_fields(
            pcap_path,
            cancellation_token=cancellation_token,
        )
        selected = [name for name in FIELD_CANDIDATES if name in supported]
        if not any(name in selected for name in CORE_FIELDS):
            raise JobExecutionError(
                JobError(
                    code="protocol_fields_unavailable",
                    category=ErrorCategory.INTERNAL,
                    message="Installed tshark does not expose required traffic metadata fields",
                    component="traffic_analysis",
                )
            )

        fd, name = tempfile.mkstemp(prefix="traffic-protocols-", suffix=".tsv", dir=pcap_path.parent)
        os.close(fd)
        output_path = Path(name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(74, "Разбираем TLS, HTTP, QUIC, SMB, DNS и DHCP")
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
            for name in selected:
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
                code = "protocol_intelligence_decode_failed"
                if result.cancelled:
                    category = ErrorCategory.CANCELLED
                    code = "cancelled"
                elif result.timed_out:
                    category = ErrorCategory.TIMEOUT
                    code = "protocol_intelligence_timeout"
                elif result.error and result.error.code.value == "missing_binary":
                    category = ErrorCategory.TOOL_MISSING
                    code = "tshark_unavailable"
                raise JobExecutionError(
                    JobError(
                        code=code,
                        category=category,
                        message=(result.error.message if result.error else "tshark protocol decode failed"),
                        component="traffic_analysis",
                        details={
                            "exit_code": result.exit_code,
                            "stderr": result.stderr[-1000:] if result.stderr else None,
                        },
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

        tls_frames = 0
        tls_sni: Counter[str] = Counter()
        tls_versions: Counter[str] = Counter()
        tls_alpn: Counter[str] = Counter()
        tls_pairs: Counter[tuple[str, str]] = Counter()

        http_requests = 0
        http_responses = 0
        http_hosts: Counter[str] = Counter()
        http_methods: Counter[str] = Counter()
        http_statuses: Counter[str] = Counter()
        http_pairs: Counter[tuple[str, str]] = Counter()

        quic_frames = 0
        quic_versions: Counter[str] = Counter()
        quic_pairs: Counter[tuple[str, str]] = Counter()

        smb_frames = 0
        smb_commands: Counter[str] = Counter()
        smb_statuses: Counter[str] = Counter()
        smb_pairs: Counter[tuple[str, str]] = Counter()
        smb_error_frames = 0

        dns_queries = 0
        dns_responses = 0
        dns_names: Counter[str] = Counter()
        dns_rcodes: Counter[str] = Counter()
        dns_clients: Counter[str] = Counter()
        dns_servers: Counter[str] = Counter()
        dns_answers: Counter[str] = Counter()

        dhcp_messages: Counter[str] = Counter()
        dhcp_servers: Counter[str] = Counter()
        dhcp_hostnames: Counter[str] = Counter()
        dhcp_transactions: defaultdict[str, list[str]] = defaultdict(list)

        def value(columns: list[str], name: str) -> str:
            position = index.get(name)
            if position is None or position >= len(columns):
                return ""
            return columns[position].strip()

        for row_number, raw in enumerate(lines, start=1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) < len(fields):
                columns.extend([""] * (len(fields) - len(columns)))

            protocols = {
                item.strip().lower()
                for item in value(columns, "frame.protocols").split(":")
                if item.strip()
            }
            source = _safe_ip(value(columns, "ip.src")) or _safe_ip(value(columns, "ipv6.src"))
            destination = _safe_ip(value(columns, "ip.dst")) or _safe_ip(value(columns, "ipv6.dst"))
            pair = _pair(source, destination)
            tcp_src = value(columns, "tcp.srcport")
            tcp_dst = value(columns, "tcp.dstport")
            udp_src = value(columns, "udp.srcport")
            udp_dst = value(columns, "udp.dstport")

            if "tls" in protocols:
                tls_frames += 1
                if pair:
                    tls_pairs[pair] += 1
                sni = value(columns, "tls.handshake.extensions_server_name").lower().rstrip(".")
                if sni:
                    tls_sni[sni] += 1
                preferred_version = (
                    value(columns, "tls.handshake.extensions.supported_version")
                    or value(columns, "tls.handshake.version")
                    or value(columns, "tls.record.version")
                )
                version = _normalize_tls_version(preferred_version)
                if version:
                    tls_versions[version] += 1
                alpn = value(columns, "tls.handshake.extensions_alpn_str")
                if alpn:
                    tls_alpn[alpn] += 1

            http_host = value(columns, "http.host").lower().rstrip(".")
            http_method = value(columns, "http.request.method").upper()
            http_status = value(columns, "http.response.code")
            if "http" in protocols or http_host or http_method or http_status:
                if pair:
                    http_pairs[pair] += 1
                if http_host:
                    http_hosts[http_host] += 1
                if http_method:
                    http_requests += 1
                    http_methods[http_method] += 1
                if http_status:
                    http_responses += 1
                    http_statuses[http_status] += 1

            quic_version = value(columns, "quic.version")
            if "quic" in protocols or quic_version:
                quic_frames += 1
                if pair:
                    quic_pairs[pair] += 1
                if quic_version:
                    quic_versions[quic_version] += 1

            smb2_cmd = _smb_command(value(columns, "smb2.cmd"))
            smb_cmd = value(columns, "smb.cmd")
            smb_status = value(columns, "smb2.nt_status") or value(columns, "smb.nt_status")
            if "smb2" in protocols or "smb" in protocols or smb2_cmd or smb_cmd:
                smb_frames += 1
                if pair:
                    smb_pairs[pair] += 1
                command = smb2_cmd or smb_cmd
                if command:
                    smb_commands[command] += 1
                if smb_status:
                    smb_statuses[smb_status] += 1
                    if _status_is_error(smb_status):
                        smb_error_frames += 1

            # Ordinary DNS only: exclude mDNS/LLMNR even though tshark may expose
            # dns.* fields for local discovery protocols.
            ordinary_dns = (
                "dns" in protocols
                and "mdns" not in protocols
                and "llmnr" not in protocols
                and (tcp_src == "53" or tcp_dst == "53" or udp_src == "53" or udp_dst == "53")
            )
            if ordinary_dns:
                name = value(columns, "dns.qry.name").lower().rstrip(".")
                response = _truthy(value(columns, "dns.flags.response"))
                rcode = value(columns, "dns.flags.rcode")
                if response:
                    dns_responses += 1
                    if source:
                        dns_servers[source] += 1
                    if rcode:
                        dns_rcodes[rcode] += 1
                    for answer_field in ("dns.a", "dns.aaaa"):
                        answer = value(columns, answer_field)
                        if answer:
                            dns_answers[answer] += 1
                else:
                    dns_queries += 1
                    if source:
                        dns_clients[source] += 1
                if name:
                    dns_names[name] += 1

            dhcp_field = value(columns, "dhcp.option.dhcp") or value(columns, "bootp.option.dhcp")
            dhcp_message = _dhcp_type(dhcp_field)
            dhcp_protocol = "dhcp" in protocols or "bootp" in protocols
            if dhcp_protocol or dhcp_message:
                if dhcp_message:
                    dhcp_messages[dhcp_message] += 1
                hostname = value(columns, "dhcp.option.hostname") or value(columns, "bootp.option.hostname")
                if hostname:
                    dhcp_hostnames[hostname] += 1
                server_id = (
                    value(columns, "dhcp.option.dhcp_server_id")
                    or value(columns, "bootp.option.dhcp_server_id")
                )
                server_ip = _safe_ip(server_id)
                if server_ip:
                    dhcp_servers[server_ip] += 1
                elif udp_src == "67" and source and source != "0.0.0.0":
                    dhcp_servers[source] += 1
                xid = value(columns, "dhcp.id") or value(columns, "bootp.id")
                if xid and dhcp_message:
                    sequence = dhcp_transactions[xid]
                    if not sequence or sequence[-1] != dhcp_message:
                        sequence.append(dhcp_message)

            if progress and row_number % 50_000 == 0:
                progress(76, f"Протокольный разбор: {row_number:,} кадров")

        http_4xx = sum(count for code, count in http_statuses.items() if code.startswith("4"))
        http_5xx = sum(count for code, count in http_statuses.items() if code.startswith("5"))
        dns_errors = sum(count for code, count in dns_rcodes.items() if code not in {"", "0"})

        legacy_tls = sum(
            count for name, count in tls_versions.items() if name in {"TLS 1.0", "TLS 1.1"}
        )

        complete_dora = 0
        incomplete_sequences: list[dict[str, Any]] = []
        for xid, sequence in dhcp_transactions.items():
            sequence_set = set(sequence)
            if {"DISCOVER", "OFFER", "REQUEST", "ACK"}.issubset(sequence_set):
                complete_dora += 1
            elif len(sequence) >= 2:
                incomplete_sequences.append({"transaction": xid, "sequence": sequence[:12]})

        observations: list[dict[str, str]] = []
        if legacy_tls:
            observations.append(
                {
                    "severity": "warning",
                    "category": "tls",
                    "title": "Наблюдались устаревшие версии TLS",
                    "fact": f"Метаданные TLS содержат {legacy_tls} наблюдений TLS 1.0/1.1.",
                    "meaning": "TLS 1.0/1.1 считаются устаревшими; однако версия должна подтверждаться полным handshake, попавшим в PCAP.",
                    "check": "Проверьте указанные SNI/пары узлов и конфигурацию TLS на соответствующем сервисе.",
                }
            )
        if http_5xx >= 3:
            observations.append(
                {
                    "severity": "warning",
                    "category": "http",
                    "title": "В HTTP наблюдались серверные ошибки 5xx",
                    "fact": f"HTTP responses: {http_responses}; ответов 5xx: {http_5xx}.",
                    "meaning": "Коды 5xx указывают на ошибку на стороне HTTP-сервиса или его upstream, если ответы полностью попали в PCAP.",
                    "check": "Сопоставьте HTTP Host и коды ответа с журналами соответствующего приложения/reverse proxy.",
                }
            )
        if dns_responses >= 5 and dns_errors >= 3 and dns_errors / dns_responses >= 0.2:
            observations.append(
                {
                    "severity": "warning",
                    "category": "dns",
                    "title": "Заметная доля обычных DNS-ответов содержит ошибки",
                    "fact": f"Обычных DNS responses: {dns_responses}; non-zero RCODE: {dns_errors}.",
                    "meaning": "Частые NXDOMAIN/SERVFAIL могут сопровождать ошибки имён, проблемы upstream DNS или некорректную конфигурацию приложений.",
                    "check": "Проверьте top DNS names/RCODE и клиентов, которые генерируют эти запросы.",
                }
            )
        if smb_frames >= 10 and smb_error_frames >= 3:
            observations.append(
                {
                    "severity": "info",
                    "category": "smb",
                    "title": "В SMB наблюдались ответы с ненулевым NT status",
                    "fact": f"SMB frames: {smb_frames}; кадров с ненулевым status: {smb_error_frames}.",
                    "meaning": "Не каждый SMB status означает неисправность; часть статусов является частью нормального протокольного обмена.",
                    "check": "Сопоставьте наиболее частые статусы и SMB-команды с конкретными парами узлов и симптомом пользователя.",
                }
            )
        if len(dhcp_servers) > 1:
            observations.append(
                {
                    "severity": "info",
                    "category": "dhcp",
                    "title": "В захвате видны несколько DHCP server identifiers",
                    "fact": "DHCP servers: " + ", ".join(server for server, _ in dhcp_servers.most_common(6)) + ".",
                    "meaning": "Это может быть штатный failover/HA или несколько DHCP-серверов в одном L2-домене; по одному PCAP rogue DHCP не доказывается.",
                    "check": "Сверьте адреса серверов с ожидаемой DHCP-архитектурой сегмента.",
                }
            )

        return {
            "tls": {
                "frames": tls_frames,
                "sni": _counter_rows(tls_sni, key="name", limit=30),
                "versions": _counter_rows(tls_versions, key="version", limit=12),
                "alpn": _counter_rows(tls_alpn, key="protocol", limit=20),
                "top_pairs": _pair_rows(tls_pairs),
                "legacy_version_observations": legacy_tls,
            },
            "http": {
                "requests": http_requests,
                "responses": http_responses,
                "hosts": _counter_rows(http_hosts, key="host", limit=30),
                "methods": _counter_rows(http_methods, key="method", limit=20),
                "status_codes": _counter_rows(http_statuses, key="code", limit=30),
                "client_errors_4xx": http_4xx,
                "server_errors_5xx": http_5xx,
                "top_pairs": _pair_rows(http_pairs),
            },
            "quic": {
                "frames": quic_frames,
                "versions": _counter_rows(quic_versions, key="version", limit=20),
                "top_pairs": _pair_rows(quic_pairs),
            },
            "smb": {
                "frames": smb_frames,
                "commands": _counter_rows(smb_commands, key="command", limit=30),
                "statuses": _counter_rows(smb_statuses, key="status", limit=30),
                "error_status_frames": smb_error_frames,
                "top_pairs": _pair_rows(smb_pairs),
            },
            "dns": {
                "queries": dns_queries,
                "responses": dns_responses,
                "names": _counter_rows(dns_names, key="name", limit=40),
                "rcodes": _counter_rows(dns_rcodes, key="rcode", limit=20),
                "clients": _counter_rows(dns_clients, key="endpoint", limit=20),
                "servers": _counter_rows(dns_servers, key="endpoint", limit=20),
                "answers": _counter_rows(dns_answers, key="address", limit=30),
                "error_responses": dns_errors,
            },
            "dhcp": {
                "messages": _counter_rows(dhcp_messages, key="type", limit=20),
                "servers": _counter_rows(dhcp_servers, key="endpoint", limit=20),
                "hostnames": _counter_rows(dhcp_hostnames, key="name", limit=30),
                "transactions_seen": len(dhcp_transactions),
                "complete_dora": complete_dora,
                "incomplete_sequences": incomplete_sequences[:20],
            },
            "observations": observations,
        }


def merge_protocol_intelligence(document: dict[str, Any], intelligence: dict[str, Any]) -> dict[str, Any]:
    document["protocol_intelligence"] = {
        key: value
        for key, value in intelligence.items()
        if key not in {"observations"}
    }
    observations = list(document.get("observations") or [])
    observations.extend(intelligence.get("observations") or [])
    document["observations"] = observations
    return document
