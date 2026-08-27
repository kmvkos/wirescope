"""Human-readable offline renderers for canonical global-analysis documents."""

from __future__ import annotations

from collections import Counter
from typing import Any


def _text(value: Any) -> str:
    return str(value if value is not None else "—")


def _status(value: Any) -> str:
    labels = {
        "consistent": "согласовано",
        "divergent": "расхождение",
        "insufficient": "недостаточно данных",
        "sufficient": "достаточно",
        "partial": "частично",
        "missing": "нет данных",
        "service_traffic_observed": "наблюдался трафик сервиса",
        "asset_traffic_observed": "наблюдался трафик asset",
        "uncorrelated": "не сопоставлено с выбранным PCAP",
    }
    raw = str(value or "unknown")
    return labels.get(raw, raw)


def _source_line(name: str, values: Any) -> str:
    items = [str(item) for item in (values or []) if item]
    return f"{name}: {', '.join(items) if items else '—'}"


def _protocols(rows: Any) -> str:
    result: list[str] = []
    for row in rows or []:
        if isinstance(row, dict):
            value = row.get("name") or row.get("protocol")
        else:
            value = row
        if value and str(value) not in result:
            result.append(str(value))
    return ", ".join(result) or "—"


def _ports(rows: Any) -> str:
    result: list[str] = []
    for row in rows or []:
        value = row.get("port") if isinstance(row, dict) else row
        if value and str(value) not in result:
            result.append(str(value))
    return ", ".join(result) or "—"


def render_text(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    audit = document.get("audit") or {}
    inputs = document.get("inputs") or {}
    operator = document.get("operator_summary") or {}
    consistency = document.get("infrastructure_consistency") or {}
    lines = [
        "WIRESCOPE — GLOBAL CORRELATION ANALYSIS",
        "=" * 44,
        f"Audit: {_text(audit.get('id'))}",
        f"Profile: {_text(audit.get('profile'))}",
        f"Interface: {_text(audit.get('interface'))}",
        f"Generated: {_text(document.get('generated_at'))}",
        f"Traffic Analysis job: {_text(inputs.get('traffic_analysis_job_id'))}",
        f"State: {'PARTIAL' if document.get('partial') else 'COMPLETE'}",
        "",
        str(operator.get("headline") or "Глобальная корреляция сохранённых результатов WireScope"),
    ]
    for item in operator.get("lines") or []:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "СВОДКА",
            "------",
            f"Inventory assets: {int(summary.get('inventory_assets') or 0)}",
            f"Assets observed in selected traffic: {int(summary.get('inventory_assets_observed_in_traffic') or 0)}",
            f"Assets not observed in selected traffic: {int(summary.get('inventory_assets_not_observed_in_traffic') or 0)}",
            f"Traffic endpoints: {int(summary.get('traffic_endpoints') or 0)}",
            f"Unmatched traffic endpoints: {int(summary.get('unmatched_traffic_endpoints') or 0)}",
            f"Inventory services: {int(summary.get('services') or 0)}",
            f"Services observed in selected traffic: {int(summary.get('services_observed_in_traffic') or 0)}",
            f"Findings: {int(summary.get('findings') or 0)}",
            f"External communications: {int(summary.get('external_communications') or 0)}",
            "",
            "INFRASTRUCTURE CONSISTENCY",
            "--------------------------",
        ]
    )
    for name in ("gateway", "dhcp", "dns"):
        row = consistency.get(name) or {}
        lines.append(f"{name.upper()}: {_status(row.get('status'))} [{_text(row.get('rule_id'))}]")
        for source, values in (row.get("sources") or {}).items():
            lines.append(f"  {_source_line(str(source), values)}")
        common = row.get("common_values") or []
        if common:
            lines.append(f"  common: {', '.join(str(value) for value in common)}")

    relevance = Counter(
        str(row.get("traffic_relevance") or "unknown")
        for row in document.get("finding_traffic_relevance") or []
        if isinstance(row, dict)
    )
    lines.extend(["", "FINDINGS ↔ TRAFFIC", "------------------"])
    if relevance:
        for key, count in sorted(relevance.items()):
            lines.append(f"{_status(key)}: {count}")
    else:
        lines.append("—")

    lines.extend(["", "EXTERNAL COMMUNICATIONS", "-----------------------"])
    external = sorted(
        [row for row in document.get("external_communications") or [] if isinstance(row, dict)],
        key=lambda row: int(row.get("bytes") or 0),
        reverse=True,
    )
    if not external:
        lines.append("—")
    for row in external[:50]:
        lines.append(
            f"asset {row.get('asset_id')} ↔ {row.get('external_endpoint')} | "
            f"{int(row.get('packets') or 0)} packets | {int(row.get('bytes') or 0)} bytes | "
            f"protocols: {_protocols(row.get('protocols'))} | ports: {_ports(row.get('ports'))}"
        )

    warnings = [str(item) for item in document.get("warnings") or [] if item]
    if warnings:
        lines.extend(["", "WARNINGS", "--------"])
        lines.extend(f"- {item}" for item in warnings)

    lines.extend(
        [
            "",
            "Примечание: отсутствие корреляции с выбранным PCAP не доказывает отсутствие asset, сервиса или finding в сети.",
            "",
        ]
    )
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    audit = document.get("audit") or {}
    inputs = document.get("inputs") or {}
    operator = document.get("operator_summary") or {}
    consistency = document.get("infrastructure_consistency") or {}
    lines = [
        "# WireScope — Global Correlation Analysis",
        "",
        f"- **Audit:** `{_text(audit.get('id'))}`",
        f"- **Profile:** {_text(audit.get('profile'))}",
        f"- **Interface:** `{_text(audit.get('interface'))}`",
        f"- **Traffic Analysis job:** `{_text(inputs.get('traffic_analysis_job_id'))}`",
        f"- **Generated:** {_text(document.get('generated_at'))}",
        f"- **State:** {'partial' if document.get('partial') else 'complete'}",
        "",
        f"## {operator.get('headline') or 'Операторская сводка'}",
        "",
    ]
    lines.extend(f"- {item}" for item in operator.get("lines") or [])
    lines.extend(
        [
            "",
            "## Сводка",
            "",
            "| Показатель | Значение |",
            "|---|---:|",
            f"| Inventory assets | {int(summary.get('inventory_assets') or 0)} |",
            f"| Assets observed in selected traffic | {int(summary.get('inventory_assets_observed_in_traffic') or 0)} |",
            f"| Assets not observed in selected traffic | {int(summary.get('inventory_assets_not_observed_in_traffic') or 0)} |",
            f"| Traffic endpoints | {int(summary.get('traffic_endpoints') or 0)} |",
            f"| Unmatched traffic endpoints | {int(summary.get('unmatched_traffic_endpoints') or 0)} |",
            f"| Inventory services | {int(summary.get('services') or 0)} |",
            f"| Services observed in selected traffic | {int(summary.get('services_observed_in_traffic') or 0)} |",
            f"| Findings | {int(summary.get('findings') or 0)} |",
            f"| External communications | {int(summary.get('external_communications') or 0)} |",
            "",
            "## Infrastructure consistency",
            "",
        ]
    )
    for name in ("gateway", "dhcp", "dns"):
        row = consistency.get(name) or {}
        lines.append(f"### {name.upper()} — {_status(row.get('status'))}")
        lines.append("")
        for source, values in (row.get("sources") or {}).items():
            lines.append(f"- {_source_line(str(source), values)}")
        common = row.get("common_values") or []
        if common:
            lines.append(f"- common: {', '.join(str(value) for value in common)}")
        lines.append("")

    lines.extend(["## Findings ↔ Traffic", ""])
    relevance = Counter(
        str(row.get("traffic_relevance") or "unknown")
        for row in document.get("finding_traffic_relevance") or []
        if isinstance(row, dict)
    )
    if relevance:
        lines.extend(f"- **{_status(key)}:** {count}" for key, count in sorted(relevance.items()))
    else:
        lines.append("—")

    lines.extend(["", "## External communications", ""])
    external = sorted(
        [row for row in document.get("external_communications") or [] if isinstance(row, dict)],
        key=lambda row: int(row.get("bytes") or 0),
        reverse=True,
    )
    if external:
        lines.extend(["| Asset | External endpoint | Packets | Bytes | Protocols | Ports |", "|---|---|---:|---:|---|---|"])
        for row in external[:50]:
            lines.append(
                f"| `{row.get('asset_id')}` | `{row.get('external_endpoint')}` | "
                f"{int(row.get('packets') or 0)} | {int(row.get('bytes') or 0)} | "
                f"{_protocols(row.get('protocols'))} | {_ports(row.get('ports'))} |"
            )
    else:
        lines.append("—")

    warnings = [str(item) for item in document.get("warnings") or [] if item]
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in warnings)

    lines.extend(
        [
            "",
            "> Отсутствие корреляции с выбранным PCAP не доказывает отсутствие asset, сервиса или finding в сети.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = ["render_text", "render_markdown"]
