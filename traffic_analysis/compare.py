"""Deterministic comparison of two persisted traffic-analysis documents."""

from __future__ import annotations

from typing import Any


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _delta(current: Any, baseline: Any, *, digits: int = 2) -> dict[str, Any]:
    current_number = _number(current)
    baseline_number = _number(baseline)
    difference = current_number - baseline_number
    percent = None
    if baseline_number:
        percent = round(difference * 100.0 / baseline_number, digits)
    return {
        "baseline": round(baseline_number, digits),
        "current": round(current_number, digits),
        "delta": round(difference, digits),
        "delta_percent": percent,
    }


def _protocol_map(document: dict[str, Any]) -> dict[str, dict[str, float]]:
    result: dict[str, dict[str, float]] = {}
    for item in document.get("protocol_distribution") or []:
        name = str(item.get("name") or "")
        if not name:
            continue
        result[name] = {
            "frames": _number(item.get("frames")),
            "percent": _number(item.get("percent")),
        }
    return result


def _node_ids(document: dict[str, Any]) -> set[str]:
    graph = document.get("communications_graph") or {}
    return {
        str(item.get("id"))
        for item in graph.get("nodes") or []
        if item.get("id")
    }


def _edge_key(item: dict[str, Any]) -> str | None:
    a = str(item.get("endpoint_a") or "")
    b = str(item.get("endpoint_b") or "")
    if not a or not b or a == b:
        return None
    return " ↔ ".join(sorted((a, b)))


def _edge_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    graph = document.get("communications_graph") or {}
    result: dict[str, dict[str, Any]] = {}
    for item in graph.get("edges") or []:
        key = _edge_key(item)
        if key:
            result[key] = item
    return result


def _observation_titles(document: dict[str, Any], severity: str | None = None) -> set[str]:
    return {
        str(item.get("title"))
        for item in document.get("observations") or []
        if item.get("title") and (severity is None or item.get("severity") == severity)
    }


def compare_traffic_analysis(
    *,
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_job_id: str | None = None,
    current_job_id: str | None = None,
) -> dict[str, Any]:
    """Compare normalized results without re-reading either PCAP."""

    base_summary = baseline.get("summary") or {}
    cur_summary = current.get("summary") or {}
    base_tcp = baseline.get("tcp") or {}
    cur_tcp = current.get("tcp") or {}
    base_dns = (baseline.get("protocol_intelligence") or {}).get("dns") or {}
    cur_dns = (current.get("protocol_intelligence") or {}).get("dns") or {}
    base_rtt = (baseline.get("tcp_latency") or {}).get("overall") or {}
    cur_rtt = (current.get("tcp_latency") or {}).get("overall") or {}
    base_bm = baseline.get("broadcast_multicast") or {}
    cur_bm = current.get("broadcast_multicast") or {}

    base_protocols = _protocol_map(baseline)
    cur_protocols = _protocol_map(current)
    protocol_rows: list[dict[str, Any]] = []
    for name in sorted(set(base_protocols) | set(cur_protocols)):
        base = base_protocols.get(name, {})
        cur = cur_protocols.get(name, {})
        protocol_rows.append(
            {
                "name": name,
                "frames": _delta(cur.get("frames"), base.get("frames"), digits=0),
                "percent": _delta(cur.get("percent"), base.get("percent")),
            }
        )
    protocol_rows.sort(
        key=lambda item: abs(float((item.get("percent") or {}).get("delta") or 0)),
        reverse=True,
    )

    base_nodes = _node_ids(baseline)
    cur_nodes = _node_ids(current)
    base_edges = _edge_map(baseline)
    cur_edges = _edge_map(current)
    new_edges = sorted(set(cur_edges) - set(base_edges))
    removed_edges = sorted(set(base_edges) - set(cur_edges))

    base_warnings = _observation_titles(baseline, "warning")
    cur_warnings = _observation_titles(current, "warning")

    result = {
        "schema": "traffic-analysis-comparison",
        "schema_version": 1,
        "baseline": {
            "job_id": baseline_job_id,
            "source": baseline.get("source") or {},
            "analyzer_version": baseline.get("analyzer_version"),
        },
        "current": {
            "job_id": current_job_id,
            "source": current.get("source") or {},
            "analyzer_version": current.get("analyzer_version"),
        },
        "traffic": {
            "frames": _delta(cur_summary.get("frame_count"), base_summary.get("frame_count"), digits=0),
            "bytes": _delta(cur_summary.get("byte_count"), base_summary.get("byte_count"), digits=0),
            "duration_seconds": _delta(cur_summary.get("duration_seconds"), base_summary.get("duration_seconds")),
            "conversation_count": _delta(cur_summary.get("conversation_count"), base_summary.get("conversation_count"), digits=0),
        },
        "network": {
            "new_endpoints": sorted(cur_nodes - base_nodes),
            "missing_endpoints": sorted(base_nodes - cur_nodes),
            "new_edges": new_edges[:100],
            "missing_edges": removed_edges[:100],
        },
        "protocols": protocol_rows[:30],
        "tcp": {
            "packets": _delta(cur_tcp.get("packets"), base_tcp.get("packets"), digits=0),
            "retransmission_percent": _delta(cur_tcp.get("retransmission_percent"), base_tcp.get("retransmission_percent")),
            "lost_segments": _delta(cur_tcp.get("lost_segments"), base_tcp.get("lost_segments"), digits=0),
            "zero_window": _delta(cur_tcp.get("zero_window"), base_tcp.get("zero_window"), digits=0),
            "resets": _delta(cur_tcp.get("resets"), base_tcp.get("resets"), digits=0),
        },
        "dns": {
            "queries": _delta(cur_dns.get("queries"), base_dns.get("queries"), digits=0),
            "responses": _delta(cur_dns.get("responses"), base_dns.get("responses"), digits=0),
            "error_responses": _delta(cur_dns.get("error_responses"), base_dns.get("error_responses"), digits=0),
        },
        "rtt": {
            "baseline_status": (baseline.get("tcp_latency") or {}).get("status"),
            "current_status": (current.get("tcp_latency") or {}).get("status"),
            "samples": _delta(cur_rtt.get("samples"), base_rtt.get("samples"), digits=0),
            "p50_ms": _delta(cur_rtt.get("p50_ms"), base_rtt.get("p50_ms")),
            "p95_ms": _delta(cur_rtt.get("p95_ms"), base_rtt.get("p95_ms")),
            "max_ms": _delta(cur_rtt.get("max_ms"), base_rtt.get("max_ms")),
        },
        "broadcast_multicast": {
            "broadcast_percent": _delta(cur_bm.get("broadcast_percent"), base_bm.get("broadcast_percent")),
            "multicast_percent": _delta(cur_bm.get("multicast_percent"), base_bm.get("multicast_percent")),
        },
        "diagnostics": {
            "new_warning_titles": sorted(cur_warnings - base_warnings),
            "resolved_warning_titles": sorted(base_warnings - cur_warnings),
        },
    }
    return result


def _signed(value: Any, suffix: str = "") -> str:
    number = _number(value)
    sign = "+" if number > 0 else ""
    if abs(number - round(number)) < 0.0001:
        return f"{sign}{int(round(number))}{suffix}"
    return f"{sign}{number:.2f}{suffix}"


def render_comparison_text(document: dict[str, Any]) -> str:
    traffic = document.get("traffic") or {}
    network = document.get("network") or {}
    tcp = document.get("tcp") or {}
    dns = document.get("dns") or {}
    rtt = document.get("rtt") or {}
    bm = document.get("broadcast_multicast") or {}
    diagnostics = document.get("diagnostics") or {}

    def delta_line(label: str, item: dict[str, Any], suffix: str = "") -> str:
        return (
            f"{label}: {item.get('baseline', 0)}{suffix} → {item.get('current', 0)}{suffix} "
            f"({_signed(item.get('delta'), suffix)})"
        )

    lines = [
        "WIRESCOPE — СРАВНЕНИЕ ДВУХ PCAP-АНАЛИЗОВ",
        "=" * 58,
        "",
        f"Baseline analysis: {str((document.get('baseline') or {}).get('job_id') or '—')[:8]}",
        f"Current analysis:  {str((document.get('current') or {}).get('job_id') or '—')[:8]}",
        "",
        "ОБЪЁМ И СТРУКТУРА",
        "-" * 58,
        delta_line("Кадры", traffic.get("frames") or {}),
        delta_line("Байты", traffic.get("bytes") or {}),
        delta_line("Длительность", traffic.get("duration_seconds") or {}, " с"),
        delta_line("Наблюдаемые связи", traffic.get("conversation_count") or {}),
        delta_line("Broadcast", bm.get("broadcast_percent") or {}, "%"),
        delta_line("Multicast", bm.get("multicast_percent") or {}, "%"),
        "",
        "ИЗМЕНЕНИЯ УЗЛОВ И СВЯЗЕЙ",
        "-" * 58,
        f"Новые endpoints: {len(network.get('new_endpoints') or [])}",
        f"Исчезнувшие endpoints: {len(network.get('missing_endpoints') or [])}",
        f"Новые связи: {len(network.get('new_edges') or [])}",
        f"Исчезнувшие связи: {len(network.get('missing_edges') or [])}",
    ]
    for label, values in (
        ("  Новые endpoints", network.get("new_endpoints") or []),
        ("  Исчезнувшие endpoints", network.get("missing_endpoints") or []),
        ("  Новые связи", network.get("new_edges") or []),
        ("  Исчезнувшие связи", network.get("missing_edges") or []),
    ):
        if values:
            lines.append(label + ":")
            lines.extend(f"    {value}" for value in values[:12])

    lines.extend([
        "",
        "TCP / DNS / RTT",
        "-" * 58,
        delta_line("TCP retransmission", tcp.get("retransmission_percent") or {}, "%"),
        delta_line("TCP lost hints", tcp.get("lost_segments") or {}),
        delta_line("TCP Zero Window", tcp.get("zero_window") or {}),
        delta_line("TCP RST", tcp.get("resets") or {}),
        delta_line("DNS error responses", dns.get("error_responses") or {}),
    ])
    if rtt.get("baseline_status") == "measured" and rtt.get("current_status") == "measured":
        lines.extend([
            delta_line("TCP ACK RTT p50", rtt.get("p50_ms") or {}, " мс"),
            delta_line("TCP ACK RTT p95", rtt.get("p95_ms") or {}, " мс"),
        ])
    else:
        lines.append(
            "TCP ACK RTT: сравнение ограничено — в одном или обоих capture недостаточно подтверждённых RTT samples."
        )

    protocols = document.get("protocols") or []
    changed_protocols = [
        item for item in protocols if abs(_number((item.get("percent") or {}).get("delta"))) >= 1.0
    ]
    lines.extend(["", "НАИБОЛЬШИЕ ИЗМЕНЕНИЯ ПРОТОКОЛОВ", "-" * 58])
    if changed_protocols:
        for item in changed_protocols[:12]:
            change = item.get("percent") or {}
            lines.append(
                f"{item.get('name', '—')}: {change.get('baseline', 0):.2f}% → {change.get('current', 0):.2f}% "
                f"({_signed(change.get('delta'), '%')})"
            )
    else:
        lines.append("Изменений доли протоколов ≥1 п.п. не выделено.")

    lines.extend(["", "ДИАГНОСТИЧЕСКИЕ ИЗМЕНЕНИЯ", "-" * 58])
    new_warnings = diagnostics.get("new_warning_titles") or []
    resolved = diagnostics.get("resolved_warning_titles") or []
    if new_warnings:
        lines.append("Новые предупреждения:")
        lines.extend(f"  + {item}" for item in new_warnings)
    if resolved:
        lines.append("Предупреждения, которых больше нет:")
        lines.extend(f"  - {item}" for item in resolved)
    if not new_warnings and not resolved:
        lines.append("Набор warning-сигналов не изменился.")

    lines.extend([
        "",
        "Важно: сравнение относится к двум конкретным интервалам и точкам захвата. Разница может быть вызвана временем, нагрузкой, фильтром или видимостью capture, а не изменением конфигурации сети.",
    ])
    return "\n".join(lines) + "\n"
