"""Operator-oriented deterministic rendering for traffic-analysis v3."""

from __future__ import annotations

from typing import Any


_PROTOCOL_LABELS = {
    "tls": "TLS/HTTPS",
    "quic": "QUIC",
    "http3": "HTTP/3",
    "http2": "HTTP/2",
    "http": "HTTP",
    "dns": "DNS",
    "mdns": "mDNS",
    "llmnr": "LLMNR",
    "nbns": "NBNS",
    "smb2": "SMB2/3",
    "smb": "SMB",
    "ssh": "SSH",
    "telnet": "Telnet",
    "ftp": "FTP",
    "ldap": "LDAP",
    "snmp": "SNMP",
    "dhcp": "DHCP",
    "bootp": "DHCP/BOOTP",
    "dhcpv6": "DHCPv6",
    "ssdp": "SSDP",
    "ntp": "NTP",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "arp": "ARP",
    "tcp": "TCP",
    "udp": "UDP",
    "ipv6": "IPv6",
    "ip": "IPv4",
}


def _bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def _duration(value: int | float | None) -> str:
    total = max(0, int(float(value or 0)))
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours} ч {minutes} мин {seconds} с"
    if minutes:
        return f"{minutes} мин {seconds} с"
    return f"{seconds} с"


def _protocol(value: str) -> str:
    return _PROTOCOL_LABELS.get(value, value.upper())


def _source(document: dict[str, Any]) -> str:
    source = document.get("source") or {}
    capture = str(source.get("capture_job_id") or "")
    return f"интерфейс {source.get('interface') or '—'}, capture {capture[:8] or '—'}"


def _protocol_list(items: list[dict[str, Any]]) -> str:
    values = [_protocol(str(item.get("name") or "")) for item in items if item.get("name")]
    return ", ".join(values) if values else "—"


def _port_list(items: list[dict[str, Any]] | list[str]) -> str:
    result: list[str] = []
    for item in items:
        if isinstance(item, str):
            value = item
        else:
            value = str(item.get("port") or "")
        if value:
            result.append(value)
    return ", ".join(result) if result else "—"


def render_text(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    diag = document.get("diagnostic_summary") or {}
    character = document.get("traffic_character") or {}
    rates = document.get("rates") or {}
    observations = document.get("observations") or []
    tcp = document.get("tcp") or {}
    tc = document.get("tcp_connections") or {}
    dns = document.get("dns") or {}
    dns_latency = document.get("dns_latency") or {}
    arp = document.get("arp") or {}
    arp_diag = document.get("arp_diagnostics") or {}
    dhcp = document.get("dhcp") or {}
    icmp = document.get("icmp") or {}
    bm = document.get("broadcast_multicast") or {}

    status_label = {
        "attention": "ТРЕБУЕТ ПРОВЕРКИ",
        "informational": "НАБЛЮДЕНИЯ ЕСТЬ, ЯВНАЯ НЕИСПРАВНОСТЬ НЕ ДОКАЗАНА",
        "clear": "ЯВНЫХ ПРОБЛЕМ ПО ТЕКУЩИМ ПРАВИЛАМ НЕ ВЫДЕЛЕНО",
    }.get(str(diag.get("status") or ""), "СОСТОЯНИЕ НЕ ОПРЕДЕЛЕНО")

    lines: list[str] = [
        "WIRESCOPE — ДИАГНОСТИКА PCAP",
        "=" * 52,
        "",
        f"Источник: {_source(document)}",
        f"Длительность: {_duration(summary.get('duration_seconds'))}",
        f"Кадров / объём: {summary.get('frame_count', 0)} / {_bytes(summary.get('byte_count'))}",
        f"Узлы: MAC {summary.get('unique_macs', 0)}, IPv4 {summary.get('unique_ipv4', 0)}, IPv6 {summary.get('unique_ipv6', 0)}",
        "",
        "КРАТКИЙ ДИАГНОЗ",
        "-" * 52,
        f"Статус: {status_label}",
        str(diag.get("headline") or ""),
        f"Интенсивность захвата: {float(rates.get('frames_per_second', 0)):.2f} пак/с; {_bytes(rates.get('bytes_per_second'))}/с",
        (
            "Структура трафика: "
            f"unicast {float(character.get('unicast_percent', 0)):.2f}%, "
            f"broadcast {float(character.get('broadcast_percent', 0)):.2f}%, "
            f"multicast {float(character.get('multicast_percent', 0)):.2f}%"
        ),
    ]

    if observations:
        lines.extend(["", "Что заслуживает внимания:"])
        for number, item in enumerate(observations[:8], start=1):
            level = "ПРОВЕРИТЬ" if item.get("severity") == "warning" else "КОНТЕКСТ"
            lines.append(f"  {number}. [{level}] {item.get('title', 'Наблюдение')}")
    else:
        lines.append("Выраженных диагностических сигналов по реализованным правилам не найдено.")

    dominant = character.get("dominant_flow") or {}
    external = character.get("external_communications") or []
    discovery = character.get("service_discovery") or []
    lines.extend(["", "ЧТО В ОСНОВНОМ ЛЕТАЛО", "-" * 52])
    if dominant:
        lines.append(
            f"Главный обмен: {dominant.get('endpoint_a')} ↔ {dominant.get('endpoint_b')} — "
            f"{_bytes(dominant.get('bytes'))}, {float(dominant.get('percent_of_capture_bytes', 0)):.1f}% всех байтов; "
            f"протоколы: {', '.join(_protocol(str(x)) for x in dominant.get('protocols', [])) or '—'}; "
            f"порты: {_port_list(dominant.get('ports') or [])}."
        )
    else:
        lines.append("Один доминирующий обмен не выделен.")

    if external:
        lines.append("Наблюдаемые связи локальных узлов с глобальными IP:")
        for item in external[:8]:
            lines.append(
                f"  {item.get('endpoint_a')} ↔ {item.get('endpoint_b')} — {_bytes(item.get('bytes'))}, "
                f"{item.get('packets', 0)} пак.; "
                f"{', '.join(_protocol(str(x)) for x in item.get('protocols', [])) or '—'}; "
                f"порты: {_port_list(item.get('ports') or [])}"
            )
    else:
        lines.append("Связи локальных узлов с глобальными IP в этом PCAP не выделены.")

    if discovery:
        lines.append("Service-discovery фон:")
        for item in discovery:
            lines.append(
                f"  {_protocol(str(item.get('protocol')))} — {item.get('frames', 0)} кадров ({float(item.get('percent', 0)):.2f}%)"
            )

    lines.extend(["", "ДИАГНОСТИЧЕСКИЕ НАБЛЮДЕНИЯ", "-" * 52])
    if not observations:
        lines.append("Нет наблюдений, требующих отдельного объяснения.")
    for number, item in enumerate(observations, start=1):
        level = "ПРОВЕРИТЬ" if item.get("severity") == "warning" else "ИНФО"
        lines.extend(
            [
                "",
                f"{number}. [{level}] {item.get('title', 'Наблюдение')}",
                f"   Факт: {item.get('fact', '—')}",
                f"   Что это может означать: {item.get('meaning', '—')}",
                f"   Что проверить: {item.get('check', '—')}",
            ]
        )

    lines.extend(["", "TCP — КАЧЕСТВО И ВИДИМОСТЬ", "-" * 52])
    lost = int(tcp.get("lost_segments") or 0)
    tcp_packets = int(tcp.get("packets") or 0)
    lost_percent = lost * 100.0 / tcp_packets if tcp_packets else 0.0
    lines.extend(
        [
            f"TCP-пакетов: {tcp_packets}",
            f"Retransmission: {tcp.get('retransmissions', 0)} ({float(tcp.get('retransmission_percent', 0)):.2f}%)",
            f"Previous/lost segment hints: {lost} ({lost_percent:.2f}%)",
            f"Duplicate ACK / out-of-order: {tcp.get('duplicate_acks', 0)} / {tcp.get('out_of_order', 0)}",
            f"Zero Window / RST: {tcp.get('zero_window', 0)} / {tcp.get('resets', 0)}",
            f"TCP streams: {tc.get('streams_seen', 0)}; начала handshake в PCAP: {tc.get('attempted_streams', 0)}; SYN/ACK: {tc.get('syn_ack_observed', 0)}",
        ]
    )
    if int(tc.get("streams_seen") or 0) and not int(tc.get("attempted_streams") or 0):
        lines.append("Оценка handshake ограничена: начало наблюдаемых TCP-сессий не попало в интервал захвата.")
    problem_pairs = tc.get("top_problem_pairs") or []
    if problem_pairs:
        lines.append("TCP-пары с дополнительными сигналами:")
        for item in problem_pairs[:10]:
            lines.append(
                f"  {item.get('endpoint_a')} ↔ {item.get('endpoint_b')}: retrans={item.get('retransmissions', 0)}, "
                f"dupACK={item.get('duplicate_acks', 0)}, ooo={item.get('out_of_order', 0)}, "
                f"zero-window={item.get('zero_window', 0)}, RST={item.get('resets', 0)}, SYN-retrans={item.get('syn_retransmissions', 0)}"
            )

    lines.extend(["", "РАЗРЕШЕНИЕ ИМЁН", "-" * 52])
    top_names = dns.get("top_names") or []
    if dns_latency.get("interpretation") == "local_name_resolution":
        lines.append(
            "В PCAP наблюдались только .local-имена. tshark timing здесь относится к локальному name-discovery и не трактуется как latency обычного DNS-резолвера."
        )
    elif int(dns_latency.get("samples") or 0):
        lines.append(
            f"DNS timing: samples {dns_latency.get('samples')}; avg {float(dns_latency.get('average_ms') or 0):.1f} мс; "
            f"p95 {float(dns_latency.get('p95_ms') or 0):.1f} мс; max {float(dns_latency.get('max_ms') or 0):.1f} мс."
        )
    else:
        lines.append("Достаточных timing-данных обычного DNS нет.")
    lines.append(f"NXDOMAIN / SERVFAIL: {dns.get('nxdomain', 0)} / {dns.get('servfail', 0)}")
    if top_names:
        lines.append("Наиболее частые наблюдаемые имена:")
        for item in top_names[:12]:
            lines.append(f"  {item.get('name', '—')} — {item.get('count', 0)}")

    lines.extend(["", "ARP / DHCP / ICMP", "-" * 52])
    lines.append(
        f"ARP requests/replies: {arp_diag.get('request_count', 0)} / {arp_diag.get('reply_count', 0)}; "
        f"IP↔MAC конфликтов: {arp.get('conflict_count', 0)}; gratuitous ARP: {arp.get('gratuitous_arp', 0)}"
    )
    unanswered = arp_diag.get("unanswered_targets") or []
    if unanswered:
        lines.append("ARP-цели без наблюдаемого ответа:")
        for item in unanswered[:10]:
            lines.append(f"  {item.get('ip', '—')} — {item.get('requests', 0)} requests")
    servers = dhcp.get("server_hints") or []
    if servers:
        lines.append("DHCP server hints:")
        for item in servers[:8]:
            lines.append(f"  {item.get('endpoint', '—')} — {item.get('frames', 0)} кадров")
    else:
        lines.append("DHCP server hints в этом интервале не выделены.")
    lines.append(f"ICMP/ICMPv6 диагностических/error-сообщений: {icmp.get('diagnostic_error_count', 0)}")

    lines.extend(["", "BROADCAST / MULTICAST", "-" * 52])
    lines.append(
        f"Broadcast: {bm.get('broadcast_frames', 0)} кадров ({float(bm.get('broadcast_percent', 0)):.2f}%), {_bytes(bm.get('broadcast_bytes'))}"
    )
    lines.append(
        f"Multicast: {bm.get('multicast_frames', 0)} кадров ({float(bm.get('multicast_percent', 0)):.2f}%), {_bytes(bm.get('multicast_bytes'))}"
    )
    multicast = bm.get("top_multicast_sources") or []
    if multicast:
        lines.append("Основные multicast-источники:")
        for item in multicast[:8]:
            lines.append(f"  {item.get('endpoint', '—')} — {item.get('frames', 0)} кадров")

    lines.extend(["", "ОСНОВНЫЕ ПРОТОКОЛЫ", "-" * 52])
    for item in (document.get("protocol_distribution") or [])[:15]:
        lines.append(
            f"{_protocol(str(item.get('name', 'other'))):<18} {item.get('frames', 0):>8} кадров  {float(item.get('percent', 0)):.2f}%"
        )

    lines.extend(["", "TOP TALKERS", "-" * 52])
    for number, item in enumerate((document.get("top_talkers") or [])[:15], start=1):
        lines.append(
            f"{number:>2}. {item.get('endpoint', '—'):<39} {_bytes(item.get('bytes')):>11}  {item.get('packets', 0)} пакетов"
        )

    lines.extend(["", "ОГРАНИЧЕНИЯ", "-" * 52])
    for item in document.get("limitations") or []:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "WireScope формирует этот разбор детерминированно из сохранённого PCAP и не генерирует новый сетевой трафик.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    diag = document.get("diagnostic_summary") or {}
    character = document.get("traffic_character") or {}
    observations = document.get("observations") or []
    tcp = document.get("tcp") or {}
    tc = document.get("tcp_connections") or {}
    dns = document.get("dns") or {}
    dns_latency = document.get("dns_latency") or {}
    bm = document.get("broadcast_multicast") or {}

    lines = [
        "# WireScope — диагностика PCAP",
        "",
        f"**Источник:** {_source(document)}",
        "",
        "## Краткий диагноз",
        "",
        f"**{diag.get('headline') or 'Диагностический итог не сформирован.'}**",
        "",
        f"- Кадров: **{summary.get('frame_count', 0)}**",
        f"- Объём: **{_bytes(summary.get('byte_count'))}**",
        f"- Длительность: **{_duration(summary.get('duration_seconds'))}**",
        f"- Unicast / broadcast / multicast: **{float(character.get('unicast_percent', 0)):.2f}% / {float(character.get('broadcast_percent', 0)):.2f}% / {float(character.get('multicast_percent', 0)):.2f}%**",
        "",
        "## Что заслуживает внимания",
        "",
    ]
    if not observations:
        lines.append("Выраженных диагностических сигналов по реализованным правилам не найдено.")
    for item in observations:
        lines.extend(
            [
                f"### {item.get('title', 'Наблюдение')}",
                "",
                f"**Факт:** {item.get('fact', '—')}",
                "",
                f"**Что это может означать:** {item.get('meaning', '—')}",
                "",
                f"**Что проверить:** {item.get('check', '—')}",
                "",
            ]
        )

    lines.extend(["## Основные обмены", ""])
    dominant = character.get("dominant_flow") or {}
    if dominant:
        lines.append(
            f"Главная пара: `{dominant.get('endpoint_a')}` ↔ `{dominant.get('endpoint_b')}` — "
            f"{_bytes(dominant.get('bytes'))}, {float(dominant.get('percent_of_capture_bytes', 0)):.1f}% всех байтов."
        )
    external = character.get("external_communications") or []
    if external:
        lines.extend(["", "### Локальные ↔ глобальные IP", "", "| Пара | Объём | Пакеты | Протоколы |", "|---|---:|---:|---|"])
        for item in external[:12]:
            lines.append(
                f"| `{item.get('endpoint_a')}` ↔ `{item.get('endpoint_b')}` | {_bytes(item.get('bytes'))} | {item.get('packets', 0)} | "
                f"{', '.join(_protocol(str(x)) for x in item.get('protocols', [])) or '—'} |"
            )

    tcp_packets = int(tcp.get("packets") or 0)
    lost = int(tcp.get("lost_segments") or 0)
    lost_percent = lost * 100.0 / tcp_packets if tcp_packets else 0.0
    lines.extend(
        [
            "",
            "## TCP",
            "",
            f"- TCP-пакетов: {tcp_packets}",
            f"- Retransmission: {tcp.get('retransmissions', 0)} ({float(tcp.get('retransmission_percent', 0)):.2f}%)",
            f"- Previous/lost segment hints: {lost} ({lost_percent:.2f}%)",
            f"- Duplicate ACK / out-of-order: {tcp.get('duplicate_acks', 0)} / {tcp.get('out_of_order', 0)}",
            f"- Zero Window / RST: {tcp.get('zero_window', 0)} / {tcp.get('resets', 0)}",
            f"- Streams / начатые handshake / SYN-ACK: {tc.get('streams_seen', 0)} / {tc.get('attempted_streams', 0)} / {tc.get('syn_ack_observed', 0)}",
            "",
            "## Разрешение имён",
            "",
        ]
    )
    if dns_latency.get("interpretation") == "local_name_resolution":
        lines.append("В захвате только `.local`-имена; timing не трактуется как latency обычного DNS-резолвера.")
    else:
        lines.append(
            f"DNS timing: samples {dns_latency.get('samples', 0)}, p95 {float(dns_latency.get('p95_ms') or 0):.1f} мс, max {float(dns_latency.get('max_ms') or 0):.1f} мс."
        )
    lines.append(f"NXDOMAIN / SERVFAIL: {dns.get('nxdomain', 0)} / {dns.get('servfail', 0)}")

    lines.extend(
        [
            "",
            "## Broadcast / multicast",
            "",
            f"- Broadcast: {float(bm.get('broadcast_percent', 0)):.2f}%",
            f"- Multicast: {float(bm.get('multicast_percent', 0)):.2f}%",
            "",
            "## Ограничения",
            "",
        ]
    )
    for item in document.get("limitations") or []:
        lines.append(f"- {item}")
    lines.extend(["", "Анализ построен только из сохранённого PCAP; новый сетевой трафик не генерировался."])
    return "\n".join(lines).rstrip() + "\n"
