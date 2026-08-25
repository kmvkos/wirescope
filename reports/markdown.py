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
    "audit_status": {
        "completed": "завершён",
        "failed": "ошибка",
        "running": "выполняется",
        "queued": "в очереди",
        "cancelled": "отменён",
        "interrupted": "прерван",
    },
    "service_state": {
        "open": "открыт",
        "closed": "закрыт",
        "filtered": "фильтруется",
        "open|filtered": "открыт или фильтруется",
        "unknown": "не определено",
    },
    "asset_state": {
        "responsive": "отвечает",
        "unresponsive": "не отвечает",
        "observed": "наблюдался",
        "up": "активен",
        "down": "неактивен",
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
        "observed": "трафик наблюдался",
        "unknown": "не определено",
    },
    "visibility": {
        "local": "локальная видимость",
        "local-segment": "локальный сегмент",
        "broadcast": "в основном широковещательный трафик",
        "limited": "ограниченная видимость",
        "unknown": "не определена",
    },
    "port_hint": {
        "access": "access-порт / нетегированный сегмент",
        "trunk": "trunk / несколько VLAN",
        "hybrid": "гибридный порт",
        "unknown": "не определён",
    },
    "naming_status": {
        "detected": "обнаружен",
        "present": "обнаружен",
        "absent": "не обнаружен",
        "not_detected": "не обнаружен",
        "unknown": "не определено",
    },
}

_SENSOR_NAMES = {
    "ethernet": "Ethernet",
    "vlan": "802.1Q VLAN",
    "arp": "ARP",
    "dhcpv4": "DHCPv4",
    "dhcpv6": "DHCPv6",
    "lldp": "LLDP",
    "cdp": "CDP",
    "stp": "STP",
    "ipv6": "IPv6 RA/ND",
    "mdns": "mDNS",
    "ssdp": "SSDP",
    "llmnr": "LLMNR",
    "nbns": "NBNS",
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


def _join(values: Any, *, empty: str = "—") -> str:
    if not isinstance(values, (list, tuple)):
        return empty
    items = [str(item) for item in values if item not in (None, "")]
    return _text(", ".join(items) if items else empty)


def _yes_no(value: Any, *, unknown: str = "не определено") -> str:
    if value is None:
        return unknown
    return "да" if bool(value) else "нет"


def _duration(value: Any) -> str:
    if value is None or value == "":
        return "—"
    try:
        seconds = max(0, int(round(float(value))))
    except (TypeError, ValueError):
        return _text(value)
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} ч {minutes:02d} мин {sec:02d} с"
    if minutes:
        return f"{minutes} мин {sec:02d} с"
    return f"{sec} с"


def render_markdown(document: dict[str, Any]) -> str:
    audit = document.get("audit") or {}
    summary = document.get("executive_summary") or {}
    environment = document.get("environment") or {}
    scope = document.get("scope") or {}
    passive = document.get("passive") or {}
    assets = document.get("assets") or []
    services = document.get("services") or []
    findings = document.get("findings") or []
    recommendations = document.get("recommendations") or []
    evidence = document.get("evidence_references") or []
    metadata = document.get("metadata") or {}
    by_severity = summary.get("by_severity") or {}

    headline = _text(human_headline(summary.get("headline")))
    summary_text = str(summary.get("summary") or "Итоговое заключение отсутствует.")
    targets = scope.get("targets") or []
    vlans = passive.get("tagged_vlan_ids") or []
    address_families = [
        "IPv4" if item == 4 else "IPv6" if item == 6 else str(item)
        for item in (scope.get("address_families") or [])
    ]

    lines = [
        "# Отчёт WireScope",
        "",
        f"> **{headline}**",
        "",
        summary_text,
        "",
        "## Краткий итог",
        "",
        f"- **Аудит:** `{_text(audit.get('id'))}`",
        f"- **Дата формирования:** {_text(document.get('generated_at'))}",
        f"- **Профиль:** {_ru('profile', audit.get('profile'))}",
        f"- **Интерфейс:** {_text(audit.get('interface'))}",
        f"- **Статус:** {_ru('audit_status', audit.get('status'))}",
        "",
        "| Показатель | Значение |",
        "| --- | ---: |",
        f"| Устройства | {_text(summary.get('asset_count'))} |",
        f"| Службы | {_text(summary.get('service_count'))} |",
        f"| Все findings | {_text(summary.get('finding_count'))} |",
        f"| Открытые проблемы | {_text(summary.get('open_finding_count'))} |",
        f"| Критические | {_text(by_severity.get('critical', 0))} |",
        f"| Высокие | {_text(by_severity.get('high', 0))} |",
        f"| Средние | {_text(by_severity.get('medium', 0))} |",
        f"| Низкие | {_text(by_severity.get('low', 0))} |",
        f"| Evidence-артефакты | {len(evidence)} |",
        "",
        "## Покрытие и ограничения",
        "",
        f"- **Scope подтверждён оператором:** {_yes_no(scope.get('confirmed'))}",
        f"- **Пассивные данные сохранены:** {_yes_no(passive.get('available'))}",
        f"- **Входные данные усечены:** {_yes_no(metadata.get('truncated'))}",
        f"- **Сырой вывод инструментов исключён из тела отчёта:** {_yes_no(metadata.get('raw_provider_output_excluded'))}",
        "",
        "> **Важно:** отсутствие зафиксированных проблем означает только, что правила WireScope не обнаружили их в доступной видимости и в рамках фактически выполненных проверок. Это не доказательство абсолютной безопасности сети.",
        "",
        "## Границы и параметры аудита",
        "",
        f"- **Профиль:** {_ru('profile', scope.get('profile'))}",
        f"- **Интерфейс:** {_text(scope.get('interface'))}",
        f"- **Количество адресов:** {_text(scope.get('address_count'))}",
        f"- **Семейства адресов:** {_text(', '.join(address_families) if address_families else '—')}",
        f"- **Политика таймингов:** {_text(scope.get('timing_policy'))}",
        f"- **Создан:** {_text(audit.get('created_at'))}",
        f"- **Начат:** {_text(audit.get('started_at'))}",
        f"- **Завершён:** {_text(audit.get('finished_at'))}",
        "",
    ]

    if targets:
        lines.extend(["**Цели:**", *[f"- `{_text(item)}`" for item in targets], ""])
    else:
        lines.extend(["**Цели:** не сохранены.", ""])

    route = environment.get("default_route") or {}
    route_text = "—"
    if isinstance(route, dict) and route:
        route_text = f"{route.get('gateway') or '—'} через {route.get('interface') or '—'}"
    lines.extend(
        [
            "## Окружение WireScope",
            "",
            f"- **Имя узла:** {_text(environment.get('hostname'))}",
            f"- **Интерфейс аудита:** {_text(environment.get('capture_interface'))}",
            f"- **L3-адрес на интерфейсе:** {_yes_no(environment.get('had_l3_address'))}",
            f"- **Маршрут по умолчанию:** {_text(route_text)}",
            f"- **DNS:** {_join(environment.get('dns'))}",
            "",
        ]
    )

    interfaces = environment.get("interfaces") or []
    if interfaces:
        lines.extend([
            "| Интерфейс | Состояние | MAC | IPv4 | IPv6 |",
            "| --- | --- | --- | --- | --- |",
        ])
        for item in interfaces:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(item.get("name")),
                        _text(item.get("state")),
                        _text(item.get("mac")),
                        _join(item.get("ipv4")),
                        _join(item.get("ipv6")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Снимок сетевых интерфейсов не сохранён.")

    capture_addresses = (passive.get("capture_ipv4") or []) + (passive.get("capture_ipv6") or [])
    sensors = [
        _SENSOR_NAMES.get(str(item).lower(), str(item))
        for item in (passive.get("detected_sensors") or [])
    ]
    lines.extend(
        [
            "",
            "## Пассивная картина сегмента",
            "",
            f"- **Данные есть:** {_yes_no(passive.get('available'))}",
            f"- **Интерфейс захвата:** {_text(passive.get('capture_interface'))}",
            f"- **Адреса интерфейса:** {_join(capture_addresses)}",
            f"- **Длительность:** {_duration(passive.get('duration_seconds'))}",
            f"- **Кадры:** {_text(passive.get('frame_count'))}",
            f"- **Состояние сегмента:** {_ru('segment', passive.get('segment_status'))}",
            f"- **Видимость:** {_ru('visibility', passive.get('visibility'))}",
            f"- **Почему так оценена видимость:** {_text(passive.get('visibility_rationale') or passive.get('segment_note'))}",
            f"- **VLAN с тегом 802.1Q:** {_text(', '.join(str(x) for x in vlans) if vlans else 'не обнаружены')}",
            f"- **Тегированных кадров:** {_text(passive.get('tagged_frame_count', 0))}",
            f"- **Нетегированный трафик:** {_yes_no(passive.get('untagged_traffic_observed'))}",
            f"- **Тип порта, предположение:** {_ru('port_hint', passive.get('port_type_hint'))}",
            f"- **ARP-узлы:** {_text(passive.get('arp_host_count'))}",
            f"- **Сработавшие сенсоры:** {_text(', '.join(sensors) if sensors else 'не зафиксированы')}",
            "",
            "> VLAN ID считается наблюдаемым только при наличии тега 802.1Q в кадре. Нетегированный трафик access-порта сам по себе не позволяет достоверно определить VLAN ID.",
            "",
        ]
    )

    neighbors = passive.get("neighbors") or []
    lines.extend(["### Соседи LLDP/CDP", ""])
    if neighbors:
        lines.extend([
            "| Протокол | Устройство | Порт | Native VLAN | Voice VLAN | PVID |",
            "| --- | --- | --- | ---: | ---: | ---: |",
        ])
        for item in neighbors:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(str(item.get("protocol") or "—").upper()),
                        _text(item.get("name")),
                        _text(item.get("port_id")),
                        _text(item.get("native_vlan")),
                        _text(item.get("voice_vlan")),
                        _text(item.get("pvid")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Соседи LLDP/CDP не зафиксированы.")

    dhcp = passive.get("dhcp") or {}
    stp = passive.get("stp") or {}
    lines.extend(
        [
            "",
            "### DHCPv4",
            "",
            f"- **Обнаружен:** {_yes_no(dhcp.get('observed'))}",
            f"- **Количество серверов:** {_text(dhcp.get('server_count', 0))}",
            f"- **Server ID:** {_join(dhcp.get('servers'))}",
            f"- **Шлюзы:** {_join(dhcp.get('routers'))}",
            f"- **Маски:** {_join(dhcp.get('subnet_masks'))}",
            "",
            "### STP",
            "",
            f"- **BPDU:** {_text(stp.get('bpdus_observed', 0))}",
            f"- **Root Bridge ID:** {_join(stp.get('root_bridge_ids'))}",
            f"- **Bridge ID:** {_join(stp.get('bridge_ids'))}",
            "",
        ]
    )

    naming = passive.get("naming") or []
    lines.extend(["### Разрешение имён в сегменте", ""])
    if naming:
        lines.extend([
            "| Протокол | Состояние | События | Имена | Адреса |",
            "| --- | --- | ---: | --- | --- |",
        ])
        names = {"mdns": "mDNS", "llmnr": "LLMNR", "nbns": "NBNS"}
        for item in naming:
            token = str(item.get("name") or "").lower()
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(names.get(token, item.get("name"))),
                        _ru("naming_status", item.get("status")),
                        _text(item.get("hits", 0)),
                        _join(item.get("names")),
                        _join(item.get("addresses")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Данные mDNS/LLMNR/NBNS не сохранены.")

    arp = passive.get("arp_bindings") or []
    lines.extend(["", "### Наблюдаемые ARP-привязки", ""])
    if arp:
        lines.extend(["| IPv4 | MAC |", "| --- | --- |"])
        for item in arp:
            lines.append(f"| `{_text(item.get('ipv4'))}` | `{_text(item.get('mac'))}` |")
    else:
        lines.append("Сохранённых ARP-привязок нет.")

    lines.extend(["", "## Устройства", ""])
    if assets:
        lines.extend([
            "| Адрес / имя | Состояние | MAC | Производитель | Тип | ОС |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for item in assets:
            labels = (item.get("names") or []) + (item.get("addresses") or [])
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(", ".join(labels[:4])),
                        _ru("asset_state", item.get("state")),
                        _text(item.get("mac")),
                        _text(item.get("vendor")),
                        _ru("device_class", item.get("device_class_hint")),
                        _text(item.get("os_name")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Устройства для этого аудита не сохранены.")

    lines.extend(["", "## Обнаруженные службы", ""])
    if services:
        lines.extend([
            "| Устройство | Порт | Служба | Продукт / версия | Туннель | Состояние |",
            "| --- | ---: | --- | --- | --- | --- |",
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
                        _text(item.get("tunnel")),
                        _ru("service_state", item.get("state")),
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
                    f"- **Версия правила:** {_text(item.get('rule_version'))}",
                    f"- **Семейство:** {_text(item.get('family'))}",
                    f"- **Статус:** {_ru('finding_status', item.get('status'))}",
                    f"- **Уверенность:** {_ru('confidence', item.get('confidence'))}",
                    f"- **Устройство:** `{_text(item.get('asset_id'))}`",
                    f"- **Служба:** `{_text(item.get('service_id'))}`",
                    f"- **Evidence:** {_join(item.get('evidence_artifact_ids'))}",
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
                    f"   - Затронутые устройства: {_join(item.get('affected_asset_ids'))}",
                ]
            )
    else:
        lines.append("Отдельных рекомендаций по открытым проблемам нет.")

    lines.extend(["", "## Evidence / доказательства", ""])
    lines.append(
        "Сырой вывод инструментов не встраивается в основной текст отчёта. Ниже перечислены зарегистрированные артефакты с контрольными суммами."
    )
    lines.append("")
    if evidence:
        lines.extend([
            "| ID | Тип | Формат | Размер, байт | SHA-256 | Создан |",
            "| --- | --- | --- | ---: | --- | --- |",
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
                        _text(item.get("created_at")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("Артефакты доказательств не зарегистрированы.")

    warnings = metadata.get("warnings") or []
    lines.extend(
        [
            "",
            "## Технические метаданные",
            "",
            f"- **ID отчёта:** `{_text(document.get('report_id'))}`",
            f"- **Source hash:** `{_text(document.get('source_hash'))}`",
            f"- **Snapshot scope:** `{_text(scope.get('snapshot_hash'))}`",
            f"- **Версия WireScope:** {_text(metadata.get('version'))}",
            f"- **Исполнитель:** {_text(metadata.get('actor'))}",
            f"- **Предупреждения генератора:** {_text('; '.join(str(x) for x in warnings) if warnings else 'нет')}",
            "",
            "---",
            "Отчёт сформирован WireScope из сохранённых данных аудита. Повторное сканирование при экспорте не выполнялось.",
            "",
        ]
    )
    return "\n".join(lines)
