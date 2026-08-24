"""Russian Markdown export for the canonical audit-report v1 document."""

from __future__ import annotations

from typing import Any

from reports.presentation import human_headline


_RU = {
    "severity": {
        "critical": "критическая",
        "high": "высокая",
        "medium": "средняя",
        "low": "низкая",
        "info": "информационная",
    },
    "finding_status": {
        "open": "открыта",
        "suppressed": "подавлена",
        "accepted_risk": "риск принят",
    },
    "confidence": {
        "confirmed": "подтверждено",
        "high": "высокая",
        "medium": "средняя",
        "low": "низкая",
        "hint": "предположение",
        "unknown": "не определена",
    },
    "profile": {
        "passive": "пассивный",
        "discovery": "обнаружение",
        "standard": "стандартный",
        "deep": "глубокий",
        "packet_capture": "запись трафика",
    },
    "status": {
        "completed": "завершён",
        "failed": "ошибка",
        "running": "выполняется",
        "queued": "в очереди",
        "cancelled": "отменён",
        "interrupted": "прерван",
        "open": "открыт",
        "closed": "закрыт",
        "filtered": "фильтруется",
        "responsive": "отвечает",
        "unresponsive": "не отвечает",
        "observed": "наблюдался",
        "unknown": "не определено",
    },
    "device_class": {
        "server-like": "сервер",
        "workstation-like": "рабочая станция",
        "network-device-like": "сетевое устройство",
        "printer-like": "принтер / МФУ",
        "iot-like": "IoT / встроенное устройство",
        "unknown": "не определён",
    },
    "segment": {
        "quiet": "тихий сегмент",
        "tagged_vlans": "обнаружены тегированные VLAN",
        "untagged_traffic": "нетегированный трафик",
        "very_low": "очень мало трафика",
        "active": "есть сетевой трафик",
        "unknown": "не определено",
    },
}


def _text(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _ru(group: str, value: Any) -> str:
    if value is None or value == "":
        return "—"
    token = str(value)
    return _RU.get(group, {}).get(token.lower(), token)


def render_markdown(document: dict[str, Any]) -> str:
    audit = document.get("audit") or {}
    summary = document.get("executive_summary") or {}
    scope = document.get("scope") or {}
    passive = document.get("passive") or {}
    assets = document.get("assets") or []
    services = document.get("services") or []
    findings = document.get("findings") or []
    recommendations = document.get("recommendations") or []
    evidence = document.get("evidence_references") or []
    by_severity = summary.get("by_severity") or {}

    headline = _text(human_headline(summary.get("headline")))
    summary_text = str(summary.get("summary") or "Итоговое заключение отсутствует.")
    targets = scope.get("targets") or []
    vlans = passive.get("tagged_vlan_ids") or []

    lines = [
        "# Отчёт WireScope",
        "",
        f"> **{headline}**",
        "",
        summary_text,
        "",
        "## Кратко",
        "",
        f"- **Аудит:** `{_text(audit.get('id'))}`",
        f"- **Дата формирования:** {_text(document.get('generated_at'))}",
        f"- **Профиль:** {_ru('profile', audit.get('profile'))}",
        f"- **Интерфейс:** {_text(audit.get('interface'))}",
        f"- **Статус:** {_ru('status', audit.get('status'))}",
        "",
        "| Показатель | Значение |",
        "| --- | ---: |",
        f"| Устройства | {_text(summary.get('asset_count'))} |",
        f"| Службы | {_text(summary.get('service_count'))} |",
        f"| Проблемы безопасности | {_text(summary.get('finding_count'))} |",
        f"| Открытые проблемы | {_text(summary.get('open_finding_count'))} |",
        f"| Критические | {_text(by_severity.get('critical', 0))} |",
        f"| Высокие | {_text(by_severity.get('high', 0))} |",
        f"| Средние | {_text(by_severity.get('medium', 0))} |",
        f"| Низкие | {_text(by_severity.get('low', 0))} |",
        "",
        "## Scope аудита",
        "",
        f"- **Подтверждён оператором:** {'да' if scope.get('confirmed') else 'нет'}",
        f"- **Профиль:** {_ru('profile', scope.get('profile'))}",
        f"- **Интерфейс:** {_text(scope.get('interface'))}",
        f"- **Количество адресов:** {_text(scope.get('address_count'))}",
        "",
    ]

    if targets:
        lines.extend(["**Цели:**", *[f"- `{_text(item)}`" for item in targets], ""])
    else:
        lines.extend(["**Цели:** не сохранены.", ""])

    lines.extend(
        [
            "## Пассивное наблюдение",
            "",
            f"- **Данные есть:** {'да' if passive.get('available') else 'нет'}",
            f"- **Кадры:** {_text(passive.get('frame_count'))}",
            f"- **Состояние сегмента:** {_ru('segment', passive.get('segment_status'))}",
            f"- **Видимость:** {_text(passive.get('visibility'))}",
            f"- **VLAN с тегом 802.1Q:** {_text(', '.join(str(x) for x in vlans) if vlans else 'не обнаружены')}",
            f"- **ARP-узлы:** {_text(passive.get('arp_host_count'))}",
            "",
            "> VLAN ID считается наблюдаемым только при наличии тега 802.1Q в кадре. Нетегированный трафик access-порта сам по себе не позволяет достоверно определить VLAN ID.",
            "",
            "## Устройства",
            "",
        ]
    )

    if assets:
        lines.extend([
            "| Адрес / имя | MAC | Производитель | Тип | ОС | Состояние |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for item in assets:
            labels = (item.get("names") or []) + (item.get("addresses") or [])
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(", ".join(labels[:4])),
                        _text(item.get("mac")),
                        _text(item.get("vendor")),
                        _ru("device_class", item.get("device_class_hint")),
                        _text(item.get("os_name")),
                        _ru("status", item.get("state")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Устройства для этого аудита не сохранены.")

    lines.extend(["", "## Обнаруженные службы", ""])
    if services:
        lines.extend([
            "| Устройство | Порт | Служба | Продукт / версия | Состояние |",
            "| --- | ---: | --- | --- | --- |",
        ])
        for item in services:
            product = " ".join(x for x in [item.get("product"), item.get("version")] if x)
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(item.get("asset_id")),
                        _text(f"{item.get('port')}/{item.get('protocol') or 'tcp'}"),
                        _text(item.get("service_name")),
                        _text(product),
                        _ru("status", item.get("state")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Открытые службы для этого аудита не сохранены.")

    lines.extend(["", "## Обнаруженные проблемы", ""])
    if findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ordered = sorted(findings, key=lambda item: (severity_order.get(str(item.get("severity")), 99), str(item.get("title") or "")))
        for item in ordered:
            sev = _ru("severity", item.get("severity")).upper()
            lines.extend(
                [
                    f"### [{sev}] {_text(item.get('title'))}",
                    "",
                    f"- **Правило:** `{_text(item.get('rule_id'))}`",
                    f"- **Статус:** {_ru('finding_status', item.get('status'))}",
                    f"- **Уверенность:** {_ru('confidence', item.get('confidence'))}",
                    f"- **Устройство:** `{_text(item.get('asset_id'))}`",
                    f"- **Служба:** `{_text(item.get('service_id'))}`",
                    "",
                    f"**Что обнаружено:** {_text(item.get('description'))}",
                    "",
                    f"**Почему это важно:** {_text(item.get('rationale'))}",
                    "",
                    f"**Что рекомендуется сделать:** {_text(item.get('recommendation'))}",
                    "",
                ]
            )
    else:
        lines.extend([
            "Открытых проблем безопасности не зафиксировано в пределах выполненных проверок.",
            "",
            "> Это не является доказательством полного отсутствия рисков: вывод относится только к фактически выполненным проверкам и подтверждённому scope.",
            "",
        ])

    lines.extend(["## План действий", ""])
    if recommendations:
        for index, item in enumerate(recommendations, 1):
            lines.extend(
                [
                    f"{index}. **[{_ru('severity', item.get('severity')).upper()}] {_text(item.get('title'))}**",
                    f"   - {_text(item.get('recommendation'))}",
                ]
            )
    else:
        lines.append("Отдельных рекомендаций по открытым проблемам нет.")

    lines.extend(["", "## Evidence / доказательства", ""])
    lines.append(
        "Сырой вывод инструментов не встраивается в отчёт. Ниже перечислены зарегистрированные артефакты с контрольными суммами."
    )
    lines.append("")
    if evidence:
        lines.extend([
            "| ID | Тип | Формат | Размер, байт | SHA-256 |",
            "| --- | --- | ---: | ---: | --- |",
        ])
        for item in evidence:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_text(item.get('id'))}`",
                        _text(item.get("artifact_type")),
                        _text(item.get("content_type")),
                        _text(item.get("size")),
                        f"`{_text(item.get('sha256'))}`",
                    ]
                )
                + " |"
            )
    else:
        lines.append("Артефакты доказательств не зарегистрированы.")

    lines.extend(
        [
            "",
            "---",
            "Отчёт сформирован WireScope из сохранённых данных аудита. Повторное сканирование при экспорте не выполнялось.",
            "",
        ]
    )
    return "\n".join(lines)
