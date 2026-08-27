"""Human-readable offline renderers for canonical global-analysis documents."""

from __future__ import annotations

from collections import Counter
from typing import Any


_SOURCE_LABELS = {
    "environment": "окружение WireScope",
    "environment_lease": "DHCP lease интерфейса",
    "passive": "пассивное наблюдение",
    "passive_dhcp": "DHCP из пассивного наблюдения",
    "traffic": "анализ PCAP",
    "topology": "топология",
}


def _text(value: Any) -> str:
    return str(value if value is not None else "—")


def _status(value: Any) -> str:
    labels = {
        "consistent": "согласовано",
        "divergent": "есть расхождение",
        "insufficient": "недостаточно данных",
        "sufficient": "достаточно данных",
        "partial": "частично",
        "missing": "нет данных",
        "service_traffic_observed": "трафик связанной службы наблюдался",
        "asset_traffic_observed": "трафик связанного устройства наблюдался",
        "uncorrelated": "не сопоставлено с выбранным PCAP",
        "unknown": "не определено",
    }
    raw = str(value or "unknown")
    return labels.get(raw, raw)


def _source_line(name: str, values: Any) -> str:
    items = [str(item) for item in (values or []) if item]
    label = _SOURCE_LABELS.get(name, name)
    return f"{label}: {', '.join(items) if items else '—'}"


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


def _operator_lines(document: dict[str, Any]) -> list[str]:
    operator = document.get("operator_summary") or {}
    lines = [str(item) for item in operator.get("lines") or [] if item]
    replacements = {
        "inventory assets": "устройств инвентаря",
        "inventory services": "служб инвентаря",
        "exact-correlated assets": "точно сопоставленными устройствами",
        "infrastructure evidence": "данных об инфраструктуре",
        "infrastructure checks": "проверок инфраструктурных данных",
        "source_health, coverage и warnings": "состояние источников, покрытие и предупреждения",
    }
    result: list[str] = []
    for line in lines:
        polished = line
        for old, new in replacements.items():
            polished = polished.replace(old, new)
        result.append(polished)
    return result


def render_text(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    audit = document.get("audit") or {}
    inputs = document.get("inputs") or {}
    consistency = document.get("infrastructure_consistency") or {}
    lines = [
        "WIRESCOPE — КОРРЕЛЯЦИЯ РЕЗУЛЬТАТОВ",
        "=" * 48,
        f"Аудит: {_text(audit.get('id'))}",
        f"Профиль: {_text(audit.get('profile'))}",
        f"Интерфейс: {_text(audit.get('interface'))}",
        f"Сформировано: {_text(document.get('generated_at'))}",
        f"Выбранный анализ PCAP: {_text(inputs.get('traffic_analysis_job_id'))}",
        f"Полнота результата: {'частичный' if document.get('partial') else 'полный'}",
        "",
        "КРАТКИЙ ИТОГ",
        "-------------",
    ]
    operator_lines = _operator_lines(document)
    if operator_lines:
        lines.extend(f"- {item}" for item in operator_lines)
    else:
        lines.append("Сопоставление выполнено по сохранённым результатам аудита, анализа PCAP и топологии.")

    lines.extend(
        [
            "",
            "СВОДКА СОПОСТАВЛЕНИЯ",
            "---------------------",
            f"Устройств в инвентаре: {int(summary.get('inventory_assets') or 0)}",
            f"Устройств, наблюдавшихся в выбранном PCAP: {int(summary.get('inventory_assets_observed_in_traffic') or 0)}",
            f"Устройств, не наблюдавшихся в выбранном PCAP: {int(summary.get('inventory_assets_not_observed_in_traffic') or 0)}",
            f"Конечных точек трафика в PCAP: {int(summary.get('traffic_endpoints') or 0)}",
            f"Конечных точек PCAP без сопоставления с инвентарём: {int(summary.get('unmatched_traffic_endpoints') or 0)}",
            f"Служб в инвентаре: {int(summary.get('services') or 0)}",
            f"Служб, использование которых наблюдалось в PCAP: {int(summary.get('services_observed_in_traffic') or 0)}",
            f"Проблем аудита: {int(summary.get('findings') or 0)}",
            f"Внешних коммуникаций у точно сопоставленных устройств: {int(summary.get('external_communications') or 0)}",
            "",
            "СОГЛАСОВАННОСТЬ ДАННЫХ ОБ ИНФРАСТРУКТУРЕ",
            "-----------------------------------------",
        ]
    )
    for name, label in (("gateway", "Шлюз"), ("dhcp", "DHCP"), ("dns", "DNS")):
        row = consistency.get(name) or {}
        lines.append(f"{label}: {_status(row.get('status'))} [{_text(row.get('rule_id'))}]")
        for source, values in (row.get("sources") or {}).items():
            lines.append(f"  {_source_line(str(source), values)}")
        common = row.get("common_values") or []
        if common:
            lines.append(f"  Совпавшие значения: {', '.join(str(value) for value in common)}")

    relevance = Counter(
        str(row.get("traffic_relevance") or "unknown")
        for row in document.get("finding_traffic_relevance") or []
        if isinstance(row, dict)
    )
    lines.extend(["", "ПРОБЛЕМЫ АУДИТА И НАБЛЮДАЕМЫЙ ТРАФИК", "--------------------------------------"])
    if relevance:
        for key, count in sorted(relevance.items()):
            lines.append(f"{_status(key)}: {count}")
    else:
        lines.append("Связей между проблемами аудита и выбранным PCAP не выделено.")

    lines.extend(["", "СВЯЗИ УСТРОЙСТВ С ВНЕШНИМИ АДРЕСАМИ", "------------------------------------"])
    external = sorted(
        [row for row in document.get("external_communications") or [] if isinstance(row, dict)],
        key=lambda row: int(row.get("bytes") or 0),
        reverse=True,
    )
    if not external:
        lines.append("Внешние коммуникации точно сопоставленных устройств не выделены.")
    for row in external[:50]:
        lines.append(
            f"устройство {row.get('asset_id')} ↔ {row.get('external_endpoint')} | "
            f"пакетов: {int(row.get('packets') or 0)} | байт: {int(row.get('bytes') or 0)} | "
            f"протоколы: {_protocols(row.get('protocols'))} | порты: {_ports(row.get('ports'))}"
        )

    warnings = [str(item) for item in document.get("warnings") or [] if item]
    if warnings:
        lines.extend(["", "ОГРАНИЧЕНИЯ И ПРЕДУПРЕЖДЕНИЯ", "---------------------------"])
        lines.extend(f"- {item}" for item in warnings)

    lines.extend(
        [
            "",
            "Важно: корреляция показывает только связи между уже сохранёнными источниками. Она не заменяет отчёт аудита и отдельный анализ PCAP. Отсутствие связи с выбранным PCAP не означает, что устройство, служба или проблема отсутствуют в сети.",
            "",
        ]
    )
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    summary = document.get("summary") or {}
    audit = document.get("audit") or {}
    inputs = document.get("inputs") or {}
    consistency = document.get("infrastructure_consistency") or {}
    lines = [
        "# WireScope — корреляция результатов",
        "",
        f"- **Аудит:** `{_text(audit.get('id'))}`",
        f"- **Профиль:** {_text(audit.get('profile'))}",
        f"- **Интерфейс:** `{_text(audit.get('interface'))}`",
        f"- **Выбранный анализ PCAP:** `{_text(inputs.get('traffic_analysis_job_id'))}`",
        f"- **Сформировано:** {_text(document.get('generated_at'))}",
        f"- **Полнота результата:** {'частичный' if document.get('partial') else 'полный'}",
        "",
        "## Краткий итог",
        "",
    ]
    operator_lines = _operator_lines(document)
    lines.extend(f"- {item}" for item in operator_lines)
    if not operator_lines:
        lines.append("- Сопоставление выполнено по сохранённым результатам аудита, анализа PCAP и топологии.")

    lines.extend(
        [
            "",
            "## Сводка сопоставления",
            "",
            "| Показатель | Значение |",
            "|---|---:|",
            f"| Устройства в инвентаре | {int(summary.get('inventory_assets') or 0)} |",
            f"| Устройства, наблюдавшиеся в выбранном PCAP | {int(summary.get('inventory_assets_observed_in_traffic') or 0)} |",
            f"| Устройства, не наблюдавшиеся в выбранном PCAP | {int(summary.get('inventory_assets_not_observed_in_traffic') or 0)} |",
            f"| Конечные точки трафика в PCAP | {int(summary.get('traffic_endpoints') or 0)} |",
            f"| Конечные точки PCAP без сопоставления с инвентарём | {int(summary.get('unmatched_traffic_endpoints') or 0)} |",
            f"| Службы в инвентаре | {int(summary.get('services') or 0)} |",
            f"| Службы, использование которых наблюдалось в PCAP | {int(summary.get('services_observed_in_traffic') or 0)} |",
            f"| Проблемы аудита | {int(summary.get('findings') or 0)} |",
            f"| Внешние коммуникации точно сопоставленных устройств | {int(summary.get('external_communications') or 0)} |",
            "",
            "## Согласованность данных об инфраструктуре",
            "",
        ]
    )
    for name, label in (("gateway", "Шлюз"), ("dhcp", "DHCP"), ("dns", "DNS")):
        row = consistency.get(name) or {}
        lines.append(f"### {label} — {_status(row.get('status'))}")
        lines.append("")
        for source, values in (row.get("sources") or {}).items():
            lines.append(f"- {_source_line(str(source), values)}")
        common = row.get("common_values") or []
        if common:
            lines.append(f"- Совпавшие значения: {', '.join(str(value) for value in common)}")
        lines.append("")

    lines.extend(["## Проблемы аудита и наблюдаемый трафик", ""])
    relevance = Counter(
        str(row.get("traffic_relevance") or "unknown")
        for row in document.get("finding_traffic_relevance") or []
        if isinstance(row, dict)
    )
    if relevance:
        lines.extend(f"- **{_status(key)}:** {count}" for key, count in sorted(relevance.items()))
    else:
        lines.append("Связей между проблемами аудита и выбранным PCAP не выделено.")

    lines.extend(["", "## Связи устройств с внешними адресами", ""])
    external = sorted(
        [row for row in document.get("external_communications") or [] if isinstance(row, dict)],
        key=lambda row: int(row.get("bytes") or 0),
        reverse=True,
    )
    if external:
        lines.extend(["| Устройство | Внешний адрес | Пакеты | Байты | Протоколы | Порты |", "|---|---|---:|---:|---|---|"])
        for row in external[:50]:
            lines.append(
                f"| `{row.get('asset_id')}` | `{row.get('external_endpoint')}` | "
                f"{int(row.get('packets') or 0)} | {int(row.get('bytes') or 0)} | "
                f"{_protocols(row.get('protocols'))} | {_ports(row.get('ports'))} |"
            )
    else:
        lines.append("Внешние коммуникации точно сопоставленных устройств не выделены.")

    warnings = [str(item) for item in document.get("warnings") or [] if item]
    if warnings:
        lines.extend(["", "## Ограничения и предупреждения", ""])
        lines.extend(f"- {item}" for item in warnings)

    lines.extend(
        [
            "",
            "> Корреляция показывает только связи между уже сохранёнными источниками. Она не заменяет отчёт аудита и отдельный анализ PCAP. Отсутствие связи с выбранным PCAP не означает, что устройство, служба или проблема отсутствуют в сети.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = ["render_text", "render_markdown"]
