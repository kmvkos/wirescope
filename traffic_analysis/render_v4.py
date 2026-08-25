"""Protocol-intelligence presentation layered over the v3 operator report."""

from __future__ import annotations

from typing import Any

from traffic_analysis.render_v3 import render_markdown as render_markdown_v3
from traffic_analysis.render_v3 import render_text as render_text_v3


def _pairs(items: list[dict[str, Any]], limit: int = 6) -> list[str]:
    return [
        f"{item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')} ({item.get('frames', 0)} кадров)"
        for item in items[:limit]
    ]


def _text_block(document: dict[str, Any]) -> str:
    pi = document.get("protocol_intelligence") or {}
    tls = pi.get("tls") or {}
    http = pi.get("http") or {}
    quic = pi.get("quic") or {}
    smb = pi.get("smb") or {}
    dns = pi.get("dns") or {}
    dhcp = pi.get("dhcp") or {}

    lines: list[str] = [
        "ПРОТОКОЛЬНЫЙ РАЗБОР",
        "-" * 52,
    ]

    lines.append("TLS / HTTPS metadata:")
    if int(tls.get("frames") or 0):
        lines.append(f"  TLS-кадров: {tls.get('frames', 0)}")
        sni = tls.get("sni") or []
        if sni:
            lines.append("  SNI / server names:")
            for item in sni[:12]:
                lines.append(f"    {item.get('name', '—')} — {item.get('count', 0)}")
        versions = tls.get("versions") or []
        if versions:
            lines.append("  Наблюдаемые TLS version metadata:")
            for item in versions[:8]:
                lines.append(f"    {item.get('version', '—')} — {item.get('count', 0)}")
        alpn = tls.get("alpn") or []
        if alpn:
            lines.append("  ALPN:")
            for item in alpn[:8]:
                lines.append(f"    {item.get('protocol', '—')} — {item.get('count', 0)}")
        pairs = _pairs(tls.get("top_pairs") or [])
        if pairs:
            lines.append("  Основные TLS-пары:")
            lines.extend(f"    {item}" for item in pairs)
    else:
        lines.append("  TLS metadata в этом PCAP не выделены.")

    lines.extend(["", "HTTP:"])
    if int(http.get("requests") or 0) or int(http.get("responses") or 0):
        lines.append(
            f"  Requests / responses: {http.get('requests', 0)} / {http.get('responses', 0)}; "
            f"4xx: {http.get('client_errors_4xx', 0)}; 5xx: {http.get('server_errors_5xx', 0)}"
        )
        hosts = http.get("hosts") or []
        if hosts:
            lines.append("  HTTP Host:")
            for item in hosts[:10]:
                lines.append(f"    {item.get('host', '—')} — {item.get('count', 0)}")
        methods = http.get("methods") or []
        if methods:
            lines.append("  Методы: " + ", ".join(f"{x.get('method')}={x.get('count')}" for x in methods[:8]))
        statuses = http.get("status_codes") or []
        if statuses:
            lines.append("  Коды ответа: " + ", ".join(f"{x.get('code')}={x.get('count')}" for x in statuses[:10]))
    else:
        lines.append("  HTTP/1.x request/response metadata не наблюдались.")

    lines.extend(["", "QUIC / HTTP3:"])
    if int(quic.get("frames") or 0):
        lines.append(f"  QUIC-кадров: {quic.get('frames', 0)}")
        versions = quic.get("versions") or []
        if versions:
            lines.append("  Версии: " + ", ".join(f"{x.get('version')}={x.get('count')}" for x in versions[:8]))
        pairs = _pairs(quic.get("top_pairs") or [])
        if pairs:
            lines.append("  Основные QUIC-пары:")
            lines.extend(f"    {item}" for item in pairs)
    else:
        lines.append("  QUIC metadata не наблюдались.")

    lines.extend(["", "SMB:"])
    if int(smb.get("frames") or 0):
        lines.append(
            f"  SMB-кадров: {smb.get('frames', 0)}; кадров с ненулевым NT status: {smb.get('error_status_frames', 0)}"
        )
        commands = smb.get("commands") or []
        if commands:
            lines.append("  Команды: " + ", ".join(f"{x.get('command')}={x.get('count')}" for x in commands[:12]))
        statuses = smb.get("statuses") or []
        if statuses:
            lines.append("  Status: " + ", ".join(f"{x.get('status')}={x.get('count')}" for x in statuses[:10]))
        pairs = _pairs(smb.get("top_pairs") or [])
        if pairs:
            lines.append("  Основные SMB-пары:")
            lines.extend(f"    {item}" for item in pairs)
    else:
        lines.append("  SMB metadata не наблюдались.")

    lines.extend(["", "Обычный DNS (port 53, без mDNS/LLMNR):"])
    if int(dns.get("queries") or 0) or int(dns.get("responses") or 0):
        lines.append(
            f"  Queries / responses: {dns.get('queries', 0)} / {dns.get('responses', 0)}; "
            f"responses с non-zero RCODE: {dns.get('error_responses', 0)}"
        )
        clients = dns.get("clients") or []
        servers = dns.get("servers") or []
        if clients:
            lines.append("  Клиенты: " + ", ".join(f"{x.get('endpoint')}={x.get('count')}" for x in clients[:8]))
        if servers:
            lines.append("  DNS-серверы: " + ", ".join(f"{x.get('endpoint')}={x.get('count')}" for x in servers[:8]))
        names = dns.get("names") or []
        if names:
            lines.append("  Top names:")
            for item in names[:12]:
                lines.append(f"    {item.get('name', '—')} — {item.get('count', 0)}")
        rcodes = dns.get("rcodes") or []
        if rcodes:
            lines.append("  RCODE: " + ", ".join(f"{x.get('rcode')}={x.get('count')}" for x in rcodes[:8]))
    else:
        lines.append("  Обычный DNS-трафик в этом интервале не наблюдался.")

    lines.extend(["", "DHCP:"])
    messages = dhcp.get("messages") or []
    if messages:
        lines.append("  Сообщения: " + ", ".join(f"{x.get('type')}={x.get('count')}" for x in messages[:10]))
        lines.append(
            f"  Транзакций: {dhcp.get('transactions_seen', 0)}; полных DISCOVER→OFFER→REQUEST→ACK: {dhcp.get('complete_dora', 0)}"
        )
        servers = dhcp.get("servers") or []
        if servers:
            lines.append("  Server identifiers: " + ", ".join(f"{x.get('endpoint')}={x.get('count')}" for x in servers[:8]))
        incomplete = dhcp.get("incomplete_sequences") or []
        if incomplete:
            lines.append("  Неполные последовательности, попавшие в PCAP:")
            for item in incomplete[:8]:
                lines.append(f"    {item.get('transaction', '—')}: {' → '.join(item.get('sequence') or [])}")
    else:
        lines.append("  DHCP message sequence в этом интервале не наблюдалась.")

    lines.extend(
        [
            "",
            "Примечание: этот раздел использует только доступные метаданные PCAP. TLS payload не расшифровывается; HTTP body/cookies и SMB filenames не извлекаются в отчёт.",
        ]
    )
    return "\n".join(lines) + "\n\n"


def render_text(document: dict[str, Any]) -> str:
    base = render_text_v3(document)
    block = _text_block(document)
    for marker in ("TCP — КАЧЕСТВО И ВИДИМОСТЬ\n", "ОГРАНИЧЕНИЯ АНАЛИЗА\n"):
        if marker in base:
            return base.replace(marker, block + marker, 1)
    return base.rstrip() + "\n\n" + block


def _markdown_block(document: dict[str, Any]) -> str:
    pi = document.get("protocol_intelligence") or {}
    tls = pi.get("tls") or {}
    http = pi.get("http") or {}
    quic = pi.get("quic") or {}
    smb = pi.get("smb") or {}
    dns = pi.get("dns") or {}
    dhcp = pi.get("dhcp") or {}

    lines = ["## Протокольный разбор", ""]
    lines.extend([
        "### TLS / HTTPS metadata",
        "",
        f"- TLS frames: {tls.get('frames', 0)}",
        "- SNI: " + (", ".join(f"`{x.get('name')}` ({x.get('count')})" for x in (tls.get('sni') or [])[:10]) or "не выделен"),
        "- TLS versions: " + (", ".join(f"{x.get('version')} ({x.get('count')})" for x in (tls.get('versions') or [])[:8]) or "не выделены"),
        "- ALPN: " + (", ".join(f"`{x.get('protocol')}` ({x.get('count')})" for x in (tls.get('alpn') or [])[:8]) or "не выделен"),
        "",
        "### HTTP",
        "",
        f"- Requests/responses: {http.get('requests', 0)} / {http.get('responses', 0)}",
        f"- 4xx / 5xx: {http.get('client_errors_4xx', 0)} / {http.get('server_errors_5xx', 0)}",
        "- Hosts: " + (", ".join(f"`{x.get('host')}` ({x.get('count')})" for x in (http.get('hosts') or [])[:10]) or "не выделены"),
        "",
        "### QUIC / SMB",
        "",
        f"- QUIC frames: {quic.get('frames', 0)}",
        f"- SMB frames: {smb.get('frames', 0)}; non-zero NT status frames: {smb.get('error_status_frames', 0)}",
        "- SMB commands: " + (", ".join(f"{x.get('command')} ({x.get('count')})" for x in (smb.get('commands') or [])[:10]) or "не выделены"),
        "",
        "### Обычный DNS",
        "",
        f"- Queries/responses: {dns.get('queries', 0)} / {dns.get('responses', 0)}",
        f"- Error responses: {dns.get('error_responses', 0)}",
        "- Servers: " + (", ".join(f"`{x.get('endpoint')}` ({x.get('count')})" for x in (dns.get('servers') or [])[:8]) or "не выделены"),
        "",
        "### DHCP",
        "",
        "- Messages: " + (", ".join(f"{x.get('type')} ({x.get('count')})" for x in (dhcp.get('messages') or [])[:10]) or "не наблюдались"),
        f"- Transactions / complete DORA: {dhcp.get('transactions_seen', 0)} / {dhcp.get('complete_dora', 0)}",
        "",
        "> Protocol Intelligence использует только метаданные PCAP; TLS payload не расшифровывается, HTTP body/cookies и SMB filenames не экспортируются.",
        "",
    ])
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    base = render_markdown_v3(document)
    block = _markdown_block(document)
    for marker in ("## TCP", "## Ограничения", "## Ограничения анализа"):
        if marker in base:
            return base.replace(marker, block + marker, 1)
    return base.rstrip() + "\n\n" + block
