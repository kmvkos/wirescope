"""Human-readable deterministic rendering for traffic-analysis v1."""

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


def _source_label(document: dict[str, Any]) -> str:
    source = document.get("source") or {}
    iface = source.get("interface") or "—"
    capture = str(source.get("capture_job_id") or "")
    short = capture[:8] if capture else "—"
    return f"интерфейс {iface}, capture {short}"


def render_text(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    tcp = document.get("tcp") or {}
    dns = document.get("dns") or {}
    arp = document.get("arp") or {}
    bm = document.get("broadcast_multicast") or {}
    dhcp = document.get("dhcp") or {}
    observations = document.get("observations") or []

    lines: list[str] = [
        "WIRESCOPE — АНАЛИЗ СЕТЕВОГО ТРАФИКА",
        "=" * 44,
        "",
        f"Источник: {_source_label(document)}",
        f"Кадров: {summary.get('frame_count', 0)}",
        f"Объём PCAP-трафика: {_bytes(summary.get('byte_count'))}",
        f"Наблюдаемая длительность: {_duration(summary.get('duration_seconds'))}",
        f"Уникальные MAC: {summary.get('unique_macs', 0)}",
        f"Уникальные IPv4: {summary.get('unique_ipv4', 0)}",
        f"Уникальные IPv6: {summary.get('unique_ipv6', 0)}",
        f"Наблюдаемые пары узлов: {summary.get('conversation_count', 0)}",
    ]
    vlans = summary.get("vlan_ids") or []
    if vlans:
        lines.append(f"VLAN ID в захвате: {', '.join(str(item) for item in vlans)}")

    lines.extend(["", "КЛЮЧЕВЫЕ НАБЛЮДЕНИЯ", "-" * 44])
    if not observations:
        lines.append(
            "Выраженных проблем по реализованным правилам не обнаружено. "
            "Это не означает, что сеть или приложения полностью исправны: вывод относится только к видимому трафику и набору выполненных проверок."
        )
    for number, observation in enumerate(observations, start=1):
        severity = "ВНИМАНИЕ" if observation.get("severity") == "warning" else "ИНФО"
        lines.extend(
            [
                "",
                f"{number}. [{severity}] {observation.get('title', 'Наблюдение')}",
                f"   Что увидели: {observation.get('fact', '—')}",
                f"   Что это может означать: {observation.get('meaning', '—')}",
                f"   Что проверить: {observation.get('check', '—')}",
            ]
        )

    lines.extend(["", "ОСНОВНЫЕ ПРОТОКОЛЫ", "-" * 44])
    protocols = document.get("protocol_distribution") or []
    if not protocols:
        lines.append("Нет данных.")
    for item in protocols[:15]:
        lines.append(
            f"{_protocol(str(item.get('name', 'other'))):<16} "
            f"{item.get('frames', 0):>9} кадров  {float(item.get('percent', 0)):.2f}%"
        )

    lines.extend(["", "TOP TALKERS", "-" * 44])
    talkers = document.get("top_talkers") or []
    if not talkers:
        lines.append("Нет адресных данных для ранжирования узлов.")
    for number, item in enumerate(talkers[:15], start=1):
        lines.append(
            f"{number:>2}. {item.get('endpoint', '—'):<39} "
            f"{_bytes(item.get('bytes')):>11}  {item.get('packets', 0)} пакетов"
        )
    if talkers:
        lines.append(
            "Примечание: объём узла — сумма байтов кадров, где узел был источником или получателем; это показатель вовлечённости в наблюдаемый обмен."
        )

    lines.extend(["", "НАИБОЛЕЕ АКТИВНЫЕ СВЯЗИ", "-" * 44])
    conversations = document.get("conversations") or []
    if not conversations:
        lines.append("Адресные пары не выделены.")
    for number, item in enumerate(conversations[:15], start=1):
        protocols_text = ", ".join(
            _protocol(str(value.get("name", "")))
            for value in (item.get("protocols") or [])[:4]
        ) or "—"
        lines.append(
            f"{number:>2}. {item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')} | "
            f"{_bytes(item.get('bytes'))}, {item.get('packets', 0)} пакетов | {protocols_text}"
        )

    lines.extend(
        [
            "",
            "TCP HEALTH",
            "-" * 44,
            f"TCP-пакетов: {tcp.get('packets', 0)}",
            f"Retransmission: {tcp.get('retransmissions', 0)} ({float(tcp.get('retransmission_percent', 0)):.2f}%)",
            f"Duplicate ACK: {tcp.get('duplicate_acks', 0)}",
            f"Out-of-order: {tcp.get('out_of_order', 0)}",
            f"Lost segment hints: {tcp.get('lost_segments', 0)}",
            f"Zero Window: {tcp.get('zero_window', 0)}",
            f"RST: {tcp.get('resets', 0)}",
        ]
    )

    lines.extend(
        [
            "",
            "DNS",
            "-" * 44,
            f"DNS query records: {dns.get('query_count', 0)}",
            f"NXDOMAIN: {dns.get('nxdomain', 0)}",
            f"SERVFAIL: {dns.get('servfail', 0)}",
        ]
    )
    for item in (dns.get("top_names") or [])[:15]:
        lines.append(f"  {item.get('name', '—')} — {item.get('count', 0)}")

    lines.extend(
        [
            "",
            "ARP / DHCP",
            "-" * 44,
            f"ARP IP↔MAC конфликтов: {arp.get('conflict_count', 0)}",
            f"Gratuitous ARP: {arp.get('gratuitous_arp', 0)}",
        ]
    )
    server_hints = dhcp.get("server_hints") or []
    if server_hints:
        lines.append("Наблюдаемые DHCP server hints:")
        for item in server_hints[:10]:
            lines.append(f"  {item.get('endpoint', '—')} — {item.get('frames', 0)} кадров server→client")
    else:
        lines.append("DHCP server hints в захвате не выделены.")

    lines.extend(
        [
            "",
            "BROADCAST / MULTICAST",
            "-" * 44,
            f"Broadcast: {bm.get('broadcast_frames', 0)} кадров, {float(bm.get('broadcast_percent', 0)):.2f}%, {_bytes(bm.get('broadcast_bytes'))}",
            f"Multicast: {bm.get('multicast_frames', 0)} кадров, {float(bm.get('multicast_percent', 0)):.2f}%, {_bytes(bm.get('multicast_bytes'))}",
        ]
    )

    lines.extend(["", "ОГРАНИЧЕНИЯ АНАЛИЗА", "-" * 44])
    for item in document.get("limitations") or []:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "Отчёт сформирован детерминированно из сохранённого PCAP. Новый сетевой трафик для этого анализа не генерировался.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    lines = [
        "# WireScope — анализ сетевого трафика",
        "",
        f"**Источник:** {_source_label(document)}",
        "",
        "## Сводка",
        "",
        f"- Кадров: **{summary.get('frame_count', 0)}**",
        f"- Объём: **{_bytes(summary.get('byte_count'))}**",
        f"- Наблюдаемая длительность: **{_duration(summary.get('duration_seconds'))}**",
        f"- Уникальные MAC / IPv4 / IPv6: **{summary.get('unique_macs', 0)} / {summary.get('unique_ipv4', 0)} / {summary.get('unique_ipv6', 0)}**",
        f"- Наблюдаемые пары узлов: **{summary.get('conversation_count', 0)}**",
        "",
        "## Ключевые наблюдения",
        "",
    ]
    observations = document.get("observations") or []
    if not observations:
        lines.append(
            "Выраженных проблем по реализованным правилам не обнаружено. Это не является доказательством полного отсутствия сетевых проблем."
        )
    for observation in observations:
        lines.extend(
            [
                f"### {observation.get('title', 'Наблюдение')}",
                "",
                f"**Что увидели:** {observation.get('fact', '—')}",
                "",
                f"**Что это может означать:** {observation.get('meaning', '—')}",
                "",
                f"**Что проверить:** {observation.get('check', '—')}",
                "",
            ]
        )

    lines.extend(["## Основные протоколы", "", "| Протокол | Кадры | Доля |", "|---|---:|---:|"])
    for item in (document.get("protocol_distribution") or [])[:20]:
        lines.append(
            f"| {_protocol(str(item.get('name', 'other')))} | {item.get('frames', 0)} | {float(item.get('percent', 0)):.2f}% |"
        )

    lines.extend(["", "## Top talkers", "", "| Узел | Пакеты | Объём |", "|---|---:|---:|"])
    for item in (document.get("top_talkers") or [])[:20]:
        lines.append(
            f"| `{item.get('endpoint', '—')}` | {item.get('packets', 0)} | {_bytes(item.get('bytes'))} |"
        )

    tcp = document.get("tcp") or {}
    dns = document.get("dns") or {}
    arp = document.get("arp") or {}
    bm = document.get("broadcast_multicast") or {}
    lines.extend(
        [
            "",
            "## TCP health",
            "",
            f"- TCP-пакетов: {tcp.get('packets', 0)}",
            f"- Retransmission: {tcp.get('retransmissions', 0)} ({float(tcp.get('retransmission_percent', 0)):.2f}%)",
            f"- Duplicate ACK: {tcp.get('duplicate_acks', 0)}",
            f"- Out-of-order: {tcp.get('out_of_order', 0)}",
            f"- Lost segment hints: {tcp.get('lost_segments', 0)}",
            f"- Zero Window: {tcp.get('zero_window', 0)}",
            f"- RST: {tcp.get('resets', 0)}",
            "",
            "## DNS / ARP / broadcast",
            "",
            f"- DNS queries: {dns.get('query_count', 0)}; NXDOMAIN: {dns.get('nxdomain', 0)}; SERVFAIL: {dns.get('servfail', 0)}",
            f"- ARP IP↔MAC conflicts: {arp.get('conflict_count', 0)}; gratuitous ARP: {arp.get('gratuitous_arp', 0)}",
            f"- Broadcast: {float(bm.get('broadcast_percent', 0)):.2f}%",
            f"- Multicast: {float(bm.get('multicast_percent', 0)):.2f}%",
            "",
            "## Ограничения",
            "",
        ]
    )
    for item in document.get("limitations") or []:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "Анализ сформирован только из сохранённого PCAP; новый сетевой трафик не генерировался.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"
