"""Extended human rendering for traffic-analysis diagnostics."""

from __future__ import annotations

from typing import Any

from traffic_analysis.render import render_markdown as render_markdown_base
from traffic_analysis.render import render_text as render_text_base


def _health_block(document: dict[str, Any]) -> list[str]:
    observations = document.get("observations") or []
    warning_count = sum(1 for item in observations if item.get("severity") == "warning")
    info_count = sum(1 for item in observations if item.get("severity") != "warning")
    rates = document.get("rates") or {}
    if warning_count:
        state = f"ТРЕБУЕТ ВНИМАНИЯ — предупреждений: {warning_count}, информационных сигналов: {info_count}"
    elif observations:
        state = f"ЯВНЫХ ПРОБЛЕМ НЕ ВЫДЕЛЕНО — информационных сигналов: {info_count}"
    else:
        state = "ЯВНЫХ ПРОБЛЕМ ПО ТЕКУЩИМ ПРАВИЛАМ НЕ ВЫДЕЛЕНО"
    return [
        "СОСТОЯНИЕ ЗАХВАТА",
        "-" * 44,
        state,
        f"Средняя интенсивность: {float(rates.get('frames_per_second', 0)):.2f} пак/с",
        f"Средняя наблюдаемая полоса: {float(rates.get('megabits_per_second', 0)):.3f} Мбит/с",
        "Важно: это оценка только по трафику, попавшему в PCAP, а не загрузка всего канала.",
    ]


def _advanced_text(document: dict[str, Any]) -> list[str]:
    tcp = document.get("tcp_connections") or {}
    dns = document.get("dns_latency") or {}
    arp = document.get("arp_diagnostics") or {}
    icmp = document.get("icmp") or {}
    bm = document.get("broadcast_multicast") or {}

    lines = [
        "РАСШИРЕННАЯ ДИАГНОСТИКА",
        "-" * 44,
        "TCP соединения:",
        f"  Потоков TCP замечено: {tcp.get('streams_seen', 0)}",
        f"  Начал handshake в захвате: {tcp.get('attempted_streams', 0)}",
        f"  SYN/ACK наблюдался: {tcp.get('syn_ack_observed', 0)}",
        f"  SYN/ACK не наблюдался: {tcp.get('no_syn_ack_observed', 0)}",
        f"  Потоков с SYN retransmission: {tcp.get('syn_retransmission_streams', 0)}",
        f"  Потоков с RST: {tcp.get('reset_streams', 0)}",
    ]
    problem_pairs = tcp.get("top_problem_pairs") or []
    if problem_pairs:
        lines.append("  TCP-пары с наибольшим количеством сигналов:")
        for item in problem_pairs[:10]:
            lines.append(
                "    "
                f"{item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')}: "
                f"retrans={item.get('retransmissions', 0)}, dupACK={item.get('duplicate_acks', 0)}, "
                f"ooo={item.get('out_of_order', 0)}, zero-window={item.get('zero_window', 0)}, "
                f"RST={item.get('resets', 0)}, SYN-retrans={item.get('syn_retransmissions', 0)}"
            )

    lines.extend(["", "DNS latency:"])
    samples = int(dns.get("samples") or 0)
    if samples:
        lines.append(
            f"  Ответов с измеренным временем: {samples}; "
            f"avg={float(dns.get('average_ms') or 0):.1f} мс, "
            f"p50={float(dns.get('p50_ms') or 0):.1f} мс, "
            f"p95={float(dns.get('p95_ms') or 0):.1f} мс, "
            f"max={float(dns.get('max_ms') or 0):.1f} мс"
        )
        slow_names = dns.get("slow_names") or []
        if slow_names:
            lines.append("  Самые медленные DNS-имена:")
            for item in slow_names[:8]:
                lines.append(
                    f"    {item.get('name', '—')}: avg {float(item.get('average_ms') or 0):.1f} мс, "
                    f"max {float(item.get('max_ms') or 0):.1f} мс, samples {item.get('samples', 0)}"
                )
    else:
        lines.append("  В захвате нет достаточных DNS timing-данных.")

    lines.extend(
        [
            "",
            "ARP:",
            f"  Requests: {arp.get('request_count', 0)}; replies: {arp.get('reply_count', 0)}",
        ]
    )
    unanswered = arp.get("unanswered_targets") or []
    if unanswered:
        lines.append("  Цели ARP, для которых ответ не наблюдался:")
        for item in unanswered[:10]:
            lines.append(f"    {item.get('ip', '—')} — requests {item.get('requests', 0)}")

    lines.extend(
        [
            "",
            "ICMP / ICMPv6:",
            f"  Диагностических/error-сообщений: {icmp.get('diagnostic_error_count', 0)}",
        ]
    )
    for item in (icmp.get("types") or [])[:10]:
        lines.append(f"    {item.get('type', '—')} — {item.get('count', 0)}")

    lines.extend(["", "Основные источники broadcast/multicast:"])
    broadcast = bm.get("top_broadcast_sources") or []
    multicast = bm.get("top_multicast_sources") or []
    if broadcast:
        lines.append("  Broadcast:")
        for item in broadcast[:8]:
            lines.append(f"    {item.get('endpoint', '—')} — {item.get('frames', 0)} кадров")
    if multicast:
        lines.append("  Multicast:")
        for item in multicast[:8]:
            lines.append(f"    {item.get('endpoint', '—')} — {item.get('frames', 0)} кадров")
    if not broadcast and not multicast:
        lines.append("  Выраженные источники не выделены.")
    return lines


def render_text(document: dict[str, Any]) -> str:
    base = render_text_base(document)
    health = "\n".join(_health_block(document)) + "\n\n"
    advanced = "\n".join(_advanced_text(document)) + "\n\n"
    marker = "КЛЮЧЕВЫЕ НАБЛЮДЕНИЯ\n"
    if marker in base:
        base = base.replace(marker, health + marker, 1)
    else:
        base = health + base
    limitations = "ОГРАНИЧЕНИЯ АНАЛИЗА\n"
    if limitations in base:
        base = base.replace(limitations, advanced + limitations, 1)
    else:
        base = base.rstrip() + "\n\n" + advanced
    return base


def render_markdown(document: dict[str, Any]) -> str:
    base = render_markdown_base(document)
    observations = document.get("observations") or []
    warning_count = sum(1 for item in observations if item.get("severity") == "warning")
    info_count = len(observations) - warning_count
    rates = document.get("rates") or {}
    tcp = document.get("tcp_connections") or {}
    dns = document.get("dns_latency") or {}
    arp = document.get("arp_diagnostics") or {}
    icmp = document.get("icmp") or {}

    health = [
        "## Состояние захвата",
        "",
        (
            f"**Требует внимания:** предупреждений {warning_count}, информационных сигналов {info_count}."
            if warning_count
            else f"**Явных проблем по текущим правилам не выделено.** Информационных сигналов: {info_count}."
        ),
        "",
        f"- Средняя интенсивность: {float(rates.get('frames_per_second', 0)):.2f} пак/с",
        f"- Средняя наблюдаемая полоса: {float(rates.get('megabits_per_second', 0)):.3f} Мбит/с",
        "- Это оценка только по кадрам внутри PCAP, а не загрузка всего физического канала.",
        "",
    ]
    advanced = [
        "## Расширенная диагностика",
        "",
        "### TCP handshake / проблемные пары",
        "",
        f"- TCP streams: {tcp.get('streams_seen', 0)}",
        f"- Начатых handshake: {tcp.get('attempted_streams', 0)}",
        f"- SYN/ACK наблюдался: {tcp.get('syn_ack_observed', 0)}",
        f"- SYN/ACK не наблюдался: {tcp.get('no_syn_ack_observed', 0)}",
        f"- Потоков с SYN retransmission: {tcp.get('syn_retransmission_streams', 0)}",
        f"- Потоков с RST: {tcp.get('reset_streams', 0)}",
        "",
    ]
    problem_pairs = tcp.get("top_problem_pairs") or []
    if problem_pairs:
        advanced.extend([
            "| Пара | Retrans | Dup ACK | OOO | Zero Window | RST | SYN retrans |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ])
        for item in problem_pairs[:15]:
            advanced.append(
                f"| `{item.get('endpoint_a', '—')}` ↔ `{item.get('endpoint_b', '—')}` | "
                f"{item.get('retransmissions', 0)} | {item.get('duplicate_acks', 0)} | "
                f"{item.get('out_of_order', 0)} | {item.get('zero_window', 0)} | "
                f"{item.get('resets', 0)} | {item.get('syn_retransmissions', 0)} |"
            )
    advanced.extend([
        "",
        "### DNS latency",
        "",
        f"- Samples: {dns.get('samples', 0)}",
        f"- Average: {float(dns.get('average_ms') or 0):.1f} мс",
        f"- p50: {float(dns.get('p50_ms') or 0):.1f} мс",
        f"- p95: {float(dns.get('p95_ms') or 0):.1f} мс",
        f"- Max: {float(dns.get('max_ms') or 0):.1f} мс",
        "",
        "### ARP / ICMP",
        "",
        f"- ARP requests/replies: {arp.get('request_count', 0)} / {arp.get('reply_count', 0)}",
        f"- ICMP diagnostic/error messages: {icmp.get('diagnostic_error_count', 0)}",
        "",
    ])

    marker = "## Ключевые наблюдения\n"
    if marker in base:
        base = base.replace(marker, "\n".join(health) + marker, 1)
    limitations = "## Ограничения\n"
    if limitations in base:
        base = base.replace(limitations, "\n".join(advanced) + limitations, 1)
    else:
        base = base.rstrip() + "\n\n" + "\n".join(advanced)
    return base
