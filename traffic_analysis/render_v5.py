"""Final Traffic Analysis presentation over protocol intelligence and RTT.

The lower renderer layers intentionally remain backward-compatible. This final
layer owns product-coherence cleanup for the operator-facing TXT/Markdown view:
remove duplicated detail blocks and normalize Russian terminology without
changing the canonical traffic-analysis JSON.
"""

from __future__ import annotations

from typing import Any

from traffic_analysis.render_v4 import render_markdown as render_markdown_v4
from traffic_analysis.render_v4 import render_text as render_text_v4


_TEXT_REPLACEMENTS = (
    ("WIRESCOPE — ДИАГНОСТИКА PCAP", "WIRESCOPE — АНАЛИЗ PCAP"),
    ("КРАТКИЙ ДИАГНОЗ", "КРАТКИЙ ИТОГ"),
    ("TOP TALKERS", "САМЫЕ АКТИВНЫЕ УЗЛЫ"),
    ("Service-discovery фон:", "Служебный discovery-трафик:"),
    ("TCP streams:", "TCP-потоки:"),
    ("ПРОТОКОЛЬНЫЙ РАЗБОР", "ПРОТОКОЛЫ И ПРИКЛАДНЫЕ МЕТАДАННЫЕ"),
    ("TLS / HTTPS metadata:", "TLS / HTTPS:"),
    ("SNI / server names:", "SNI / имена серверов:"),
    ("Наблюдаемые TLS version metadata:", "Версии TLS:"),
    ("Requests / responses:", "Запросы / ответы:"),
    ("HTTP Host:", "Хосты HTTP:"),
    ("QUIC / HTTP3:", "QUIC / HTTP/3:"),
    ("Status:", "Статусы:"),
    ("Обычный DNS (port 53, без mDNS/LLMNR):", "Обычный DNS (порт 53, без mDNS/LLMNR):"),
    ("Queries / responses:", "Запросы / ответы:"),
    ("Top names:", "Частые имена:"),
    ("Server identifiers:", "Идентификаторы серверов:"),
    ("TCP RTT / LATENCY HINTS", "TCP RTT — ЗАДЕРЖКИ"),
    ("ACK RTT samples:", "Выборка ACK RTT:"),
    ("samples ", "выборок "),
    ("Важно: ACK RTT — метрика видимого TCP-обмена в точке захвата. Это не latency приложения и не доказательство проблемы сети.", "Важно: ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."),
)

_MARKDOWN_REPLACEMENTS = (
    ("# WireScope — диагностика PCAP", "# WireScope — анализ PCAP"),
    ("## Краткий диагноз", "## Краткий итог"),
    ("## TCP RTT / latency hints", "## TCP RTT — задержки"),
    ("- ACK RTT samples:", "- Выборка ACK RTT:"),
    ("- Average / p50 / p95 / max:", "- Среднее / p50 / p95 / максимум:"),
    ("| Pair | Samples | p50 ms | p95 ms | max ms |", "| Пара | Выборки | p50, мс | p95, мс | максимум, мс |"),
    ("- RTT not evaluated: insufficient/unsupported ACK RTT metadata in this PCAP.", "- RTT не оценён: в PCAP недостаточно данных ACK RTT или установленный tshark их не предоставляет."),
    ("> ACK RTT is a capture-side TCP observation. It is not application latency and does not by itself prove a network fault.", "> ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."),
    ("### TLS / HTTPS metadata", "### TLS / HTTPS"),
    ("- TLS frames:", "- Кадры TLS:"),
    ("- TLS versions:", "- Версии TLS:"),
    ("- Requests/responses:", "- Запросы/ответы:"),
    ("- Hosts:", "- Хосты:"),
    ("- QUIC frames:", "- Кадры QUIC:"),
    ("- SMB frames:", "- Кадры SMB:"),
    ("- Error responses:", "- Ответы с ошибкой:"),
    ("- Servers:", "- Серверы:"),
    ("- Messages:", "- Сообщения:"),
    ("- Transactions / complete DORA:", "- Транзакции / полный DORA:"),
)


def _rtt_text(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["TCP RTT — ЗАДЕРЖКИ", "-" * 52]
    if status == "measured":
        lines.append(
            f"Выборка ACK RTT: {overall.get('samples', 0)}; среднее {float(overall.get('average_ms') or 0):.1f} мс; "
            f"p50 {float(overall.get('p50_ms') or 0):.1f} мс; p95 {float(overall.get('p95_ms') or 0):.1f} мс; "
            f"максимум {float(overall.get('max_ms') or 0):.1f} мс."
        )
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.append("Пары с наибольшим наблюдаемым p95 ACK RTT:")
            for item in pairs[:10]:
                lines.append(
                    f"  {item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')}: "
                    f"выборок {item.get('samples', 0)}, p50 {float(item.get('p50_ms') or 0):.1f} мс, "
                    f"p95 {float(item.get('p95_ms') or 0):.1f} мс, максимум {float(item.get('max_ms') or 0):.1f} мс"
                )
    elif status == "insufficient":
        lines.append("RTT не оценён: в PCAP меньше трёх подтверждённых значений tcp.analysis.ack_rtt.")
    else:
        lines.append("RTT не оценён: установленный tshark не предоставил tcp.analysis.ack_rtt или слой анализа недоступен.")
    lines.append(
        "Важно: ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."
    )
    return "\n".join(lines) + "\n\n"


def _deduplicate_text(base: str) -> str:
    """Remove detail blocks already owned by Protocol Intelligence."""

    lines = base.splitlines()
    result: list[str] = []
    skip_indented = False

    for line in lines:
        stripped = line.strip()

        if stripped == "Наиболее частые наблюдаемые имена:":
            skip_indented = True
            continue
        if stripped == "DHCP server hints:":
            skip_indented = True
            continue
        if stripped == "DHCP server hints в этом интервале не выделены.":
            continue

        if skip_indented:
            if line.startswith("  "):
                continue
            skip_indented = False

        if stripped == "ARP / DHCP / ICMP":
            line = line.replace("ARP / DHCP / ICMP", "ARP / ICMP")

        result.append(line)

    return "\n".join(result).rstrip() + "\n"


def _polish_text(value: str) -> str:
    result = value
    for old, new in _TEXT_REPLACEMENTS:
        result = result.replace(old, new)
    return result


def _polish_markdown(value: str) -> str:
    result = value
    for old, new in _MARKDOWN_REPLACEMENTS:
        result = result.replace(old, new)
    return result


def render_text(document: dict[str, Any]) -> str:
    base = _deduplicate_text(render_text_v4(document))
    block = _rtt_text(document)
    marker = "ПРОТОКОЛЬНЫЙ РАЗБОР\n"
    if marker in base:
        rendered = base.replace(marker, block + marker, 1)
    else:
        rendered = base.rstrip() + "\n\n" + block
    return _polish_text(rendered)


def _rtt_markdown(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["## TCP RTT — задержки", ""]
    if status == "measured":
        lines.extend([
            f"- Выборка ACK RTT: {overall.get('samples', 0)}",
            f"- Среднее / p50 / p95 / максимум: {float(overall.get('average_ms') or 0):.1f} / {float(overall.get('p50_ms') or 0):.1f} / {float(overall.get('p95_ms') or 0):.1f} / {float(overall.get('max_ms') or 0):.1f} мс",
            "",
        ])
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.extend([
                "| Пара | Выборки | p50, мс | p95, мс | максимум, мс |",
                "|---|---:|---:|---:|---:|",
            ])
            for item in pairs[:15]:
                lines.append(
                    f"| `{item.get('endpoint_a', '—')}` ↔ `{item.get('endpoint_b', '—')}` | "
                    f"{item.get('samples', 0)} | {float(item.get('p50_ms') or 0):.1f} | "
                    f"{float(item.get('p95_ms') or 0):.1f} | {float(item.get('max_ms') or 0):.1f} |"
                )
            lines.append("")
    else:
        lines.extend(["- RTT не оценён: в PCAP недостаточно данных ACK RTT или установленный tshark их не предоставляет.", ""])
    lines.extend([
        "> ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети.",
        "",
    ])
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    base = render_markdown_v4(document)
    block = _rtt_markdown(document)
    marker = "## Протокольный разбор"
    if marker in base:
        rendered = base.replace(marker, block + marker, 1)
    else:
        rendered = base.rstrip() + "\n\n" + block
    return _polish_markdown(rendered)
