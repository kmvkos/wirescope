"""RTT presentation layered over the protocol-intelligence v4 report."""

from __future__ import annotations

from typing import Any

from traffic_analysis.render_v4 import render_markdown as render_markdown_v4
from traffic_analysis.render_v4 import render_text as render_text_v4


def _rtt_text(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["TCP RTT / LATENCY HINTS", "-" * 52]
    if status == "measured":
        lines.append(
            f"ACK RTT samples: {overall.get('samples', 0)}; avg {float(overall.get('average_ms') or 0):.1f} мс; "
            f"p50 {float(overall.get('p50_ms') or 0):.1f} мс; p95 {float(overall.get('p95_ms') or 0):.1f} мс; "
            f"max {float(overall.get('max_ms') or 0):.1f} мс."
        )
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.append("Пары с наибольшим наблюдаемым p95 ACK RTT:")
            for item in pairs[:10]:
                lines.append(
                    f"  {item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')}: "
                    f"samples {item.get('samples', 0)}, p50 {float(item.get('p50_ms') or 0):.1f} мс, "
                    f"p95 {float(item.get('p95_ms') or 0):.1f} мс, max {float(item.get('max_ms') or 0):.1f} мс"
                )
    elif status == "insufficient":
        lines.append("RTT не оценён: в PCAP меньше трёх подтверждённых tcp.analysis.ack_rtt samples.")
    else:
        lines.append("RTT не оценён: установленный tshark не предоставил tcp.analysis.ack_rtt или слой недоступен.")
    lines.append(
        "Важно: ACK RTT — метрика видимого TCP-обмена в точке захвата. Это не latency приложения и не доказательство проблемы сети."
    )
    return "\n".join(lines) + "\n\n"


def render_text(document: dict[str, Any]) -> str:
    base = render_text_v4(document)
    block = _rtt_text(document)
    marker = "ПРОТОКОЛЬНЫЙ РАЗБОР\n"
    if marker in base:
        return base.replace(marker, block + marker, 1)
    return base.rstrip() + "\n\n" + block


def _rtt_markdown(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["## TCP RTT / latency hints", ""]
    if status == "measured":
        lines.extend([
            f"- ACK RTT samples: {overall.get('samples', 0)}",
            f"- Average / p50 / p95 / max: {float(overall.get('average_ms') or 0):.1f} / {float(overall.get('p50_ms') or 0):.1f} / {float(overall.get('p95_ms') or 0):.1f} / {float(overall.get('max_ms') or 0):.1f} ms",
            "",
        ])
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.extend([
                "| Pair | Samples | p50 ms | p95 ms | max ms |",
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
        lines.extend(["- RTT not evaluated: insufficient/unsupported ACK RTT metadata in this PCAP.", ""])
    lines.extend([
        "> ACK RTT is a capture-side TCP observation. It is not application latency and does not by itself prove a network fault.",
        "",
    ])
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    base = render_markdown_v4(document)
    block = _rtt_markdown(document)
    marker = "## Протокольный разбор"
    if marker in base:
        return base.replace(marker, block + marker, 1)
    return base.rstrip() + "\n\n" + block
