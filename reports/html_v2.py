"""Modern self-contained Russian HTML presentation for audit-report v1.

The canonical JSON document remains unchanged. This module is presentation
only: it never scans the network, reads provider stdout, or invents facts.
Every network-derived value is escaped before rendering.
"""

from __future__ import annotations

from datetime import datetime
import html
import json
from typing import Any

from reports.models import AuditReport, ReportFinding
from reports.presentation import human_headline


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_RU = {
    "severity": {
        "critical": "Критическая",
        "high": "Высокая",
        "medium": "Средняя",
        "low": "Низкая",
        "info": "Информационная",
    },
    "finding_status": {
        "open": "Открыта",
        "suppressed": "Подавлена",
        "accepted_risk": "Риск принят",
    },
    "audit_status": {
        "completed": "Завершён",
        "failed": "Ошибка",
        "running": "Выполняется",
        "queued": "В очереди",
        "cancelled": "Отменён",
        "interrupted": "Прерван",
    },
    "service_state": {
        "open": "Открыт",
        "closed": "Закрыт",
        "filtered": "Фильтруется",
        "open|filtered": "Открыт или фильтруется",
        "unknown": "Не определено",
    },
    "asset_state": {
        "responsive": "Отвечает",
        "unresponsive": "Не отвечает",
        "observed": "Наблюдался",
        "unknown": "Не определено",
        "up": "Активен",
        "down": "Неактивен",
    },
    "confidence": {
        "confirmed": "Подтверждено",
        "high": "Высокая",
        "medium": "Средняя",
        "low": "Низкая",
        "hint": "Предположение",
        "unknown": "Не определена",
    },
    "profile": {
        "passive": "Пассивный",
        "discovery": "Обнаружение",
        "standard": "Стандартный",
        "deep": "Глубокий",
        "packet_capture": "Запись трафика",
    },
    "device_class": {
        "server-like": "Сервер",
        "workstation-like": "Рабочая станция",
        "network-device-like": "Сетевое устройство",
        "printer-like": "Принтер / МФУ",
        "iot-like": "IoT / встроенное устройство",
        "unknown": "Не определён",
    },
    "segment": {
        "quiet": "Тихий сегмент",
        "tagged_vlans": "Обнаружены тегированные VLAN",
        "untagged_traffic": "Нетегированный трафик",
        "very_low": "Очень мало трафика",
        "active": "Есть сетевой трафик",
        "observed": "Трафик наблюдался",
        "unknown": "Не определено",
    },
    "visibility": {
        "local": "Локальная видимость",
        "local-segment": "Локальный сегмент",
        "broadcast": "В основном широковещательный трафик",
        "limited": "Ограниченная видимость",
        "unknown": "Не определена",
    },
    "port_hint": {
        "access": "Access-порт / нетегированный сегмент",
        "trunk": "Trunk / несколько VLAN",
        "hybrid": "Гибридный порт",
        "unknown": "Не определён",
    },
    "naming_status": {
        "detected": "Обнаружен",
        "present": "Обнаружен",
        "absent": "Не обнаружен",
        "not_detected": "Не обнаружен",
        "unknown": "Не определено",
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


def _e(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return html.escape(str(value), quote=True)


def _ru(group: str, value: Any) -> str:
    if value is None or value == "":
        return "—"
    token = str(value)
    return html.escape(_RU.get(group, {}).get(token.lower(), token), quote=True)


def _date(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return _e(value)
    suffix = " UTC" if dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0 else ""
    return html.escape(dt.strftime("%d.%m.%Y %H:%M") + suffix)


def _elapsed(start: datetime | None, end: datetime | None) -> str:
    if not start or not end:
        return "—"
    seconds = max(0, int((end - start).total_seconds()))
    return _duration(seconds)


def _duration(value: float | int | None) -> str:
    if value is None:
        return "—"
    seconds = max(0, int(round(float(value))))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} ч {minutes:02d} мин {sec:02d} с"
    if minutes:
        return f"{minutes} мин {sec:02d} с"
    return f"{sec} с"


def _count(value: int, one: str, few: str, many: str) -> str:
    n = abs(int(value)) % 100
    if 11 <= n <= 14:
        word = many
    else:
        tail = n % 10
        word = one if tail == 1 else few if tail in {2, 3, 4} else many
    return f"{value} {word}"


def _bytes(value: int) -> str:
    size = float(value or 0)
    units = ("Б", "КиБ", "МиБ", "ГиБ")
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    return f"{size:.0f} {unit}" if unit == "Б" else f"{size:.1f} {unit}"


def _yes_no(value: bool | None, *, unknown: str = "Не определено") -> str:
    if value is None:
        return unknown
    return "Да" if value else "Нет"


def _join(values: list[Any] | tuple[Any, ...], *, empty: str = "—") -> str:
    items = [str(item) for item in values if item not in (None, "")]
    return _e(", ".join(items) if items else empty)


def _paragraphs(text: str) -> str:
    parts = [part.strip() for part in (text or "").split("\n\n") if part.strip()]
    return "".join(f"<p>{_e(part)}</p>" for part in parts)


def _risk_banner(report: AuditReport) -> tuple[str, str]:
    severity = report.executive_summary.highest_open_severity
    open_count = report.executive_summary.open_finding_count
    if severity == "critical":
        return "critical", "Есть критические проблемы. Их следует разобрать в первую очередь."
    if severity == "high":
        return "high", "Есть проблемы высокой важности. Рекомендуется запланировать исправление в ближайшее время."
    if severity == "medium":
        return "medium", "Обнаружены проблемы средней важности. Они требуют проверки и планового исправления."
    if open_count:
        return "low", "Открытые замечания есть, но критических и высоких проблем не зафиксировано."
    return "ok", "Открытых проблем безопасности не зафиксировано в пределах выполненных проверок."


def _finding_card(item: ReportFinding) -> str:
    target = ""
    if item.asset_id:
        target += f"<span><b>Устройство:</b> {_e(item.asset_id)}</span>"
    if item.service_id:
        target += f"<span><b>Служба:</b> {_e(item.service_id)}</span>"
    data = ""
    if item.data:
        encoded = json.dumps(item.data, ensure_ascii=False, indent=2, sort_keys=True, default=str)
        data = (
            '<details class="technical"><summary>Технические данные правила</summary>'
            f"<pre>{_e(encoded)}</pre></details>"
        )
    evidence = ""
    if item.evidence_artifact_ids:
        evidence = (
            '<div class="finding-evidence"><b>Доказательства:</b> '
            + _join(item.evidence_artifact_ids)
            + "</div>"
        )
    return (
        f'<article class="finding severity-{_e(item.severity)}">'
        '<div class="finding-head">'
        f'<span class="severity-badge severity-{_e(item.severity)}">{_ru("severity", item.severity)}</span>'
        f'<span class="status-badge">{_ru("finding_status", item.status)}</span>'
        f'<span class="confidence">Уверенность: {_ru("confidence", item.confidence)}</span>'
        "</div>"
        f"<h3>{_e(item.title)}</h3>"
        f'<p class="rule-id">Правило {_e(item.rule_id)} · версия {_e(item.rule_version)} · семейство {_e(item.family)}</p>'
        f'<div class="finding-target">{target}</div>'
        f'<div class="finding-block"><h4>Что обнаружено</h4><p>{_e(item.description)}</p></div>'
        f'<div class="finding-block"><h4>Почему это важно</h4><p>{_e(item.rationale)}</p></div>'
        f'<div class="finding-block action"><h4>Что рекомендуется сделать</h4><p>{_e(item.recommendation)}</p></div>'
        f"{evidence}{data}"
        "</article>"
    )


def _environment_table(report: AuditReport) -> str:
    rows = []
    for iface in report.environment.interfaces:
        rows.append(
            "<tr>"
            f"<td><strong>{_e(iface.name)}</strong></td>"
            f"<td>{_e(iface.state)}</td>"
            f'<td class="mono">{_e(iface.mac)}</td>'
            f"<td>{_join(iface.ipv4)}</td>"
            f"<td>{_join(iface.ipv6)}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="empty">Снимок сетевых интерфейсов не сохранён.</p>'
    return (
        '<div class="table-wrap"><table><thead><tr><th>Интерфейс</th><th>Состояние</th><th>MAC</th><th>IPv4</th><th>IPv6</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _neighbor_table(report: AuditReport) -> str:
    rows = []
    for item in report.passive.neighbors:
        vlans = []
        if item.native_vlan is not None:
            vlans.append(f"native {item.native_vlan}")
        if item.voice_vlan is not None:
            vlans.append(f"voice {item.voice_vlan}")
        if item.pvid is not None:
            vlans.append(f"PVID {item.pvid}")
        rows.append(
            "<tr>"
            f"<td><strong>{_e(item.protocol.upper())}</strong></td>"
            f"<td>{_e(item.name)}</td>"
            f'<td class="mono">{_e(item.port_id)}</td>'
            f"<td>{_e(', '.join(vlans) if vlans else '—')}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="empty">Соседи LLDP/CDP не зафиксированы.</p>'
    return (
        '<div class="table-wrap"><table><thead><tr><th>Протокол</th><th>Устройство</th><th>Порт</th><th>VLAN</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _arp_table(report: AuditReport) -> str:
    rows = []
    for item in report.passive.arp_bindings:
        rows.append(
            f'<tr><td class="mono">{_e(item.get("ipv4"))}</td><td class="mono">{_e(item.get("mac"))}</td></tr>'
        )
    if not rows:
        return '<p class="empty">Сохранённых ARP-привязок нет.</p>'
    return (
        '<div class="table-wrap compact-table"><table><thead><tr><th>IPv4</th><th>MAC</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _naming_table(report: AuditReport) -> str:
    rows = []
    names = {"mdns": "mDNS", "llmnr": "LLMNR", "nbns": "NBNS"}
    for item in report.passive.naming:
        rows.append(
            "<tr>"
            f"<td><strong>{_e(names.get(item.name.lower(), item.name))}</strong></td>"
            f"<td>{_ru('naming_status', item.status)}</td>"
            f"<td>{item.hits}</td>"
            f"<td>{_join(item.names)}</td>"
            f"<td>{_join(item.addresses)}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="empty">Данные mDNS/LLMNR/NBNS не сохранены.</p>'
    return (
        '<div class="table-wrap"><table><thead><tr><th>Протокол</th><th>Состояние</th><th>События</th><th>Имена</th><th>Адреса</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def render_html(report: AuditReport) -> str:
    summary = report.executive_summary
    passive = report.passive
    environment = report.environment
    risk_class, risk_text = _risk_banner(report)
    by_severity = summary.by_severity or {}
    findings = sorted(
        report.findings,
        key=lambda item: (_SEVERITY_ORDER.get(item.severity, 99), item.title.lower()),
    )

    stats = "".join(
        [
            f'<div class="metric"><span>Устройства</span><strong>{summary.asset_count}</strong></div>',
            f'<div class="metric"><span>Службы</span><strong>{summary.service_count}</strong></div>',
            f'<div class="metric"><span>Открытые проблемы</span><strong>{summary.open_finding_count}</strong></div>',
            f'<div class="metric critical"><span>Критические</span><strong>{by_severity.get("critical", 0)}</strong></div>',
            f'<div class="metric high"><span>Высокие</span><strong>{by_severity.get("high", 0)}</strong></div>',
            f'<div class="metric medium"><span>Средние</span><strong>{by_severity.get("medium", 0)}</strong></div>',
            f'<div class="metric"><span>Доказательства</span><strong>{len(report.evidence_references)}</strong></div>',
        ]
    )

    coverage = "".join(
        [
            '<div class="coverage-card"><span>Scope подтверждён</span><strong>' + _yes_no(report.scope.confirmed) + '</strong><small>Активные проверки относятся только к подтверждённым целям.</small></div>',
            '<div class="coverage-card"><span>Пассивные данные</span><strong>' + ("Есть" if passive.available else "Нет") + '</strong><small>' + _e(passive.segment_note) + '</small></div>',
            '<div class="coverage-card"><span>Полнота данных</span><strong>' + ("Ограничена" if report.metadata.truncated else "Без усечения") + '</strong><small>WireScope явно отмечает усечение входных данных.</small></div>',
            '<div class="coverage-card"><span>Сырые выводы</span><strong>В evidence</strong><small>В тело отчёта не встраиваются, чтобы сохранить читаемость.</small></div>',
        ]
    )

    targets = "".join(f'<span class="chip mono">{_e(item)}</span>' for item in report.scope.targets)
    if not targets:
        targets = '<span class="muted">Цели не сохранены</span>'

    asset_rows = []
    for asset in report.assets:
        label = ", ".join(asset.names[:2] or asset.addresses[:2]) or asset.id
        asset_rows.append(
            "<tr>"
            f"<td><strong>{_e(label)}</strong><small>{_e(asset.id)}</small></td>"
            f"<td>{_ru('asset_state', asset.state)}</td>"
            f"<td>{_join(asset.addresses)}</td>"
            f'<td class="mono">{_e(asset.mac)}</td>'
            f"<td>{_e(asset.vendor)}</td>"
            f"<td>{_ru('device_class', asset.device_class_hint)}</td>"
            f"<td>{_e(asset.os_name)}</td>"
            "</tr>"
        )
    assets = (
        '<div class="table-wrap"><table><thead><tr><th>Устройство</th><th>Состояние</th><th>Адреса</th><th>MAC</th><th>Производитель</th><th>Тип</th><th>ОС</th></tr></thead><tbody>'
        + "".join(asset_rows)
        + "</tbody></table></div>"
        if asset_rows else '<p class="empty">Устройства для этого аудита не сохранены.</p>'
    )

    service_rows = []
    for service in report.services:
        product = " ".join(x for x in (service.product, service.version) if x) or "—"
        service_rows.append(
            "<tr>"
            f'<td class="mono">{_e(service.asset_id)}</td>'
            f"<td><strong>{_e(service.port)}/{_e(service.protocol)}</strong></td>"
            f"<td>{_e(service.service_name)}</td>"
            f"<td>{_e(product)}</td>"
            f"<td>{_e(service.tunnel)}</td>"
            f"<td>{_ru('service_state', service.state)}</td>"
            "</tr>"
        )
    services = (
        '<div class="table-wrap"><table><thead><tr><th>Устройство</th><th>Порт</th><th>Служба</th><th>Продукт / версия</th><th>Туннель</th><th>Состояние</th></tr></thead><tbody>'
        + "".join(service_rows)
        + "</tbody></table></div>"
        if service_rows else '<p class="empty">Открытые службы не сохранены.</p>'
    )

    finding_html = "".join(_finding_card(item) for item in findings)
    if not finding_html:
        finding_html = (
            '<div class="empty success"><strong>Открытых проблем не зафиксировано.</strong>'
            '<span>Это относится только к фактически выполненным проверкам и не является доказательством полного отсутствия рисков.</span></div>'
        )

    recs = []
    for index, item in enumerate(report.recommendations, 1):
        recs.append(
            '<li class="recommendation">'
            f'<span class="rec-number">{index}</span><div>'
            f'<div class="rec-title"><span class="severity-dot severity-{_e(item.severity)}"></span><strong>{_e(item.title)}</strong></div>'
            f'<p>{_e(item.recommendation)}</p>'
            f'<small>{_count(len(item.finding_ids), "связанная проблема", "связанные проблемы", "связанных проблем")} · '
            f'{_count(len(item.affected_asset_ids), "затронутое устройство", "затронутых устройства", "затронутых устройств")}</small>'
            "</div></li>"
        )
    recommendations = "".join(recs) or '<p class="empty">Отдельных рекомендаций по открытым проблемам нет.</p>'

    families = []
    for family in report.scope.address_families:
        families.append("IPv4" if family == 4 else "IPv6" if family == 6 else str(family))
    scope_details = (
        '<div class="detail-grid">'
        f'<div><span>Подтверждён оператором</span><strong>{_yes_no(report.scope.confirmed)}</strong></div>'
        f'<div><span>Профиль</span><strong>{_ru("profile", report.scope.profile)}</strong></div>'
        f'<div><span>Интерфейс</span><strong>{_e(report.scope.interface)}</strong></div>'
        f'<div><span>Адресов в scope</span><strong>{_e(report.scope.address_count)}</strong></div>'
        f'<div><span>Семейства адресов</span><strong>{_e(", ".join(families) if families else "—")}</strong></div>'
        f'<div><span>Политика таймингов</span><strong>{_e(report.scope.timing_policy)}</strong></div>'
        "</div>"
    )

    route = environment.default_route or {}
    route_text = "—"
    if route:
        gateway = route.get("gateway") or "—"
        iface = route.get("interface") or "—"
        route_text = f"{gateway} через {iface}"
    environment_summary = (
        '<div class="detail-grid">'
        f'<div><span>Имя узла WireScope</span><strong>{_e(environment.hostname)}</strong></div>'
        f'<div><span>Интерфейс аудита</span><strong>{_e(environment.capture_interface)}</strong></div>'
        f'<div><span>L3-адрес на интерфейсе</span><strong>{_yes_no(environment.had_l3_address)}</strong></div>'
        f'<div><span>Маршрут по умолчанию</span><strong>{_e(route_text)}</strong></div>'
        f'<div class="wide"><span>DNS</span><strong>{_join(environment.dns)}</strong></div>'
        "</div>"
    )

    vlan_text = ", ".join(str(item) for item in passive.tagged_vlan_ids) or "Не обнаружены"
    capture_addresses = list(passive.capture_ipv4) + list(passive.capture_ipv6)
    passive_details = (
        '<div class="detail-grid">'
        f'<div><span>Интерфейс захвата</span><strong>{_e(passive.capture_interface)}</strong></div>'
        f'<div><span>Длительность</span><strong>{_e(_duration(passive.duration_seconds))}</strong></div>'
        f'<div><span>Кадры</span><strong>{_e(passive.frame_count)}</strong></div>'
        f'<div><span>Адреса интерфейса</span><strong>{_join(capture_addresses)}</strong></div>'
        f'<div><span>Состояние сегмента</span><strong>{_ru("segment", passive.segment_status)}</strong></div>'
        f'<div><span>Видимость</span><strong>{_ru("visibility", passive.visibility)}</strong></div>'
        f'<div><span>VLAN с тегом 802.1Q</span><strong>{_e(vlan_text)}</strong></div>'
        f'<div><span>Тегированных кадров</span><strong>{passive.tagged_frame_count}</strong></div>'
        f'<div><span>Нетегированный трафик</span><strong>{_yes_no(passive.untagged_traffic_observed)}</strong></div>'
        f'<div><span>Тип порта, предположение</span><strong>{_ru("port_hint", passive.port_type_hint)}</strong></div>'
        f'<div><span>ARP-узлы</span><strong>{passive.arp_host_count}</strong></div>'
        f'<div><span>L3-адрес</span><strong>{_yes_no(passive.had_l3_address)}</strong></div>'
        "</div>"
    )

    sensors = "".join(
        f'<span class="chip sensor">{_e(_SENSOR_NAMES.get(name.lower(), name))}</span>'
        for name in passive.detected_sensors
    ) or '<span class="muted">Сработавшие пассивные сенсоры не зафиксированы.</span>'

    dhcp = passive.dhcp
    dhcp_summary = (
        '<div class="protocol-card">'
        '<div class="protocol-title"><span>DHCPv4</span><strong>' + ("Обнаружен" if dhcp.observed else "Не обнаружен") + '</strong></div>'
        f'<dl><dt>Серверов</dt><dd>{dhcp.server_count}</dd><dt>Server ID</dt><dd>{_join(dhcp.servers)}</dd><dt>Шлюзы</dt><dd>{_join(dhcp.routers)}</dd><dt>Маски</dt><dd>{_join(dhcp.subnet_masks)}</dd></dl>'
        "</div>"
    )
    stp = passive.stp
    stp_summary = (
        '<div class="protocol-card">'
        '<div class="protocol-title"><span>STP</span><strong>' + ("Наблюдался" if stp.bpdus_observed else "Не наблюдался") + '</strong></div>'
        f'<dl><dt>BPDU</dt><dd>{stp.bpdus_observed}</dd><dt>Root bridge</dt><dd>{_join(stp.root_bridge_ids)}</dd><dt>Bridge ID</dt><dd>{_join(stp.bridge_ids)}</dd></dl>'
        "</div>"
    )

    evidence_rows = []
    for item in report.evidence_references:
        evidence_rows.append(
            "<tr>"
            f'<td class="mono">{_e(item.id)}</td><td>{_e(item.artifact_type)}</td>'
            f'<td>{_e(item.content_type)}</td><td>{_e(_bytes(item.size))}</td>'
            f'<td class="mono hash">{_e(item.sha256)}</td><td>{_date(item.created_at)}</td>'
            "</tr>"
        )
    evidence = (
        '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Тип</th><th>Формат</th><th>Размер</th><th>SHA-256</th><th>Создан</th></tr></thead><tbody>'
        + "".join(evidence_rows) + "</tbody></table></div>"
        if evidence_rows else '<p class="empty">Артефакты доказательств не зарегистрированы.</p>'
    )

    warnings = "".join(f"<li>{_e(item)}</li>" for item in report.metadata.warnings) or "<li>Нет</li>"
    audit_scope_json = json.dumps(report.scope.audit_scope, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    snapshot = report.scope.snapshot_hash or "—"

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireScope — отчёт аудита {_e(report.audit.id)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">
<header class="hero">
  <div class="brand-row"><div class="brand-lockup"><span class="brand-mark">W</span><div><span class="brand">WireScope</span><span class="brand-sub">Отчёт сетевого аудита</span></div></div><span class="report-version">audit-report v{report.schema_version}</span></div>
  <div class="hero-main"><div><p class="eyebrow">Итог аудита</p><h1>{_e(human_headline(summary.headline))}</h1><p class="hero-copy">Ниже — выводы только по фактически выполненным проверкам и сохранённым данным. Отчёт не подменяет ручной анализ и не утверждает отсутствие рисков вне подтверждённого scope.</p></div></div>
  <div class="hero-meta"><span><b>Аудит</b> {_e(report.audit.id)}</span><span><b>Профиль</b> {_ru('profile', report.audit.profile)}</span><span><b>Интерфейс</b> {_e(report.audit.interface)}</span><span><b>Сформирован</b> {_date(report.generated_at)}</span></div>
</header>

<nav class="toc" aria-label="Разделы отчёта">
<a href="#executive-summary">Итог</a><a href="#coverage">Покрытие</a><a href="#findings">Проблемы</a><a href="#recommendations">Что делать</a><a href="#assets">Устройства</a><a href="#services">Службы</a><a href="#environment">Окружение</a><a href="#passive">Сегмент</a><a href="#technical">Техническое</a>
</nav>

<main>
<section id="executive-summary" class="section prominent">
  <div class="section-head"><div><p class="kicker">Главное</p><h2>Результат аудита</h2></div></div>
  <div class="risk-banner {risk_class}"><span class="risk-icon"></span><div><strong>{_e(risk_text)}</strong><span>Приоритет определяется по открытым проблемам и только в пределах выполненного аудита.</span></div></div>
  <div class="metrics">{stats}</div>
  <div class="summary-copy">{_paragraphs(summary.summary)}</div>
</section>

<section id="coverage" class="section">
  <div class="section-head"><div><p class="kicker">Как читать результат</p><h2>Покрытие и ограничения</h2></div></div>
  <div class="coverage-grid">{coverage}</div>
  <div class="notice"><strong>Важно.</strong> «Проблем не найдено» означает только, что правила WireScope не зафиксировали их в доступной видимости и в рамках выполненных стадий. Это не доказательство абсолютной безопасности сети.</div>
</section>

<section id="findings" class="section">
  <div class="section-head"><div><p class="kicker">Безопасность</p><h2>Обнаруженные проблемы</h2></div><span class="section-count">{len(findings)}</span></div>
  <p class="section-intro">Каждая запись объясняет, что обнаружено, почему это важно и что рекомендуется сделать. Технические значения правила доступны внутри карточки.</p>
  <div class="finding-list">{finding_html}</div>
</section>

<section id="recommendations" class="section">
  <div class="section-head"><div><p class="kicker">План действий</p><h2>Что исправлять</h2></div></div>
  <p class="section-intro">Начинайте с критических и высоких проблем. После исправления повторите аудит и сравните результаты.</p>
  <ol class="recommendations">{recommendations}</ol>
</section>

<section id="scope" class="section">
  <div class="section-head"><div><p class="kicker">Методика</p><h2>Границы и параметры аудита</h2></div></div>
  {scope_details}
  <div class="chips">{targets}</div>
  <div class="runline"><span>Создан: <b>{_date(report.audit.created_at)}</b></span><span>Начат: <b>{_date(report.audit.started_at)}</b></span><span>Завершён: <b>{_date(report.audit.finished_at)}</b></span><span>Длительность: <b>{_e(_elapsed(report.audit.started_at, report.audit.finished_at))}</b></span></div>
</section>

<section id="assets" class="section">
  <div class="section-head"><div><p class="kicker">Инвентаризация</p><h2>Устройства</h2></div><span class="section-count">{len(report.assets)}</span></div>
  <p class="section-intro">Идентификаторы, адреса, производитель, предполагаемый тип и ОС собраны из нормализованных наблюдений WireScope.</p>
  {assets}
</section>

<section id="services" class="section">
  <div class="section-head"><div><p class="kicker">Поверхность сети</p><h2>Обнаруженные службы</h2></div><span class="section-count">{len(report.services)}</span></div>
  {services}
</section>

<section id="environment" class="section">
  <div class="section-head"><div><p class="kicker">Точка наблюдения</p><h2>Окружение WireScope</h2></div></div>
  {environment_summary}
  <h3 class="subhead">Интерфейсы устройства</h3>
  {_environment_table(report)}
</section>

<section id="passive" class="section">
  <div class="section-head"><div><p class="kicker">Пассивное наблюдение</p><h2>Картина сетевого сегмента</h2></div></div>
  {passive_details}
  <div class="context-note"><strong>Оценка видимости.</strong> {_e(passive.visibility_rationale or passive.segment_note)}</div>
  <div class="sensor-row"><span class="sensor-label">Сработавшие сенсоры</span><div class="chips">{sensors}</div></div>
  <div class="protocol-grid">{dhcp_summary}{stp_summary}</div>
  <h3 class="subhead">Соседи LLDP/CDP</h3>
  {_neighbor_table(report)}
  <h3 class="subhead">Разрешение имён в локальном сегменте</h3>
  {_naming_table(report)}
  <h3 class="subhead">Наблюдаемые ARP-привязки</h3>
  {_arp_table(report)}
  <p class="note">{_e(passive.vlan_tag_note)} Нетегированный трафик access-порта не позволяет достоверно определить VLAN ID без дополнительных данных коммутатора.</p>
</section>

<section id="technical" class="section technical-section">
  <div class="section-head"><div><p class="kicker">Для проверки и воспроизводимости</p><h2>Технические данные</h2></div></div>
  <details open><summary>Evidence / доказательства ({len(report.evidence_references)})</summary><p class="note">Сырой вывод инструментов не встраивается в основной текст. Здесь перечислены зарегистрированные артефакты, их размер и контрольная сумма.</p>{evidence}</details>
  <details><summary>Метаданные отчёта</summary><dl class="metadata"><dt>ID отчёта</dt><dd>{_e(report.report_id)}</dd><dt>Source hash</dt><dd class="mono">{_e(report.source_hash)}</dd><dt>Snapshot scope</dt><dd class="mono">{_e(snapshot)}</dd><dt>Статус аудита</dt><dd>{_ru('audit_status', report.audit.status)}</dd><dt>Исполнитель</dt><dd>{_e(report.metadata.actor)}</dd><dt>Версия WireScope</dt><dd>{_e(report.metadata.version)}</dd><dt>Сырой вывод исключён из тела</dt><dd>{_yes_no(report.metadata.raw_provider_output_excluded)}</dd><dt>Данные усечены</dt><dd>{_yes_no(report.metadata.truncated)}</dd></dl></details>
  <details><summary>Исходный audit scope</summary><pre>{_e(audit_scope_json)}</pre></details>
  <details><summary>Предупреждения генератора</summary><ul>{warnings}</ul></details>
</section>
</main>

<footer><div><strong>WireScope</strong><span>Сетевой аудит · отчёт из сохранённых данных</span></div><span class="mono">source {_e(report.source_hash[:16])}</span></footer>
</div>
</body>
</html>
"""


_CSS = r"""
:root{color-scheme:light;--ink:#172033;--muted:#68758a;--line:#e0e7f0;--surface:#fff;--soft:#f6f8fb;--soft2:#eef4fa;--navy:#091a2d;--navy2:#123653;--blue:#2563eb;--cyan:#0891b2;--green:#15803d;--amber:#b45309;--red:#b42318;--red2:#7f1d1d;--radius:18px;--shadow:0 14px 42px rgba(15,23,42,.075)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:linear-gradient(180deg,#edf3f8,#f7f9fc 32%,#eef3f8);color:var(--ink);font:15px/1.56 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}.page{max-width:1220px;margin:auto;padding:28px}.hero{position:relative;overflow:hidden;background:radial-gradient(700px 300px at 93% -20%,rgba(34,211,238,.22),transparent 65%),linear-gradient(135deg,#081729,#102d4c 62%,#0c5369);color:#fff;border-radius:25px;padding:28px 30px;box-shadow:0 24px 68px rgba(15,23,42,.19)}.hero:after{content:"";position:absolute;inset:auto -12% -65% 35%;height:250px;border-radius:50%;background:rgba(45,212,191,.075);filter:blur(18px)}.brand-row,.brand-lockup,.hero-meta,.section-head,.finding-head,.finding-target,.rec-title,.protocol-title,.runline,footer{display:flex;align-items:center}.brand-row{position:relative;z-index:1;justify-content:space-between;gap:20px}.brand-lockup{gap:11px}.brand-mark{width:37px;height:37px;display:grid;place-items:center;border-radius:11px;background:linear-gradient(135deg,#5eead4,#38bdf8);color:#06211f;font-weight:900;font-size:18px;box-shadow:0 10px 28px rgba(45,212,191,.22)}.brand{font-weight:850;font-size:22px;letter-spacing:-.035em}.brand-sub{display:block;color:#b9cbe0;font-size:12px;margin-top:1px}.report-version{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.075);border-radius:999px;padding:6px 10px;font:11px ui-monospace,monospace;color:#dceafb}.hero-main{position:relative;z-index:1;display:grid;grid-template-columns:1fr;gap:24px;margin:35px 0 24px}.eyebrow,.kicker{margin:0 0 7px;text-transform:uppercase;letter-spacing:.11em;font-size:10px;font-weight:850}.eyebrow{color:#7dd3fc}.hero h1{font-size:36px;line-height:1.1;letter-spacing:-.04em;margin:0;max-width:900px}.hero-copy{color:#c8d8e8;max-width:880px;margin:14px 0 0}.hero-meta{position:relative;z-index:1;gap:10px 24px;flex-wrap:wrap;color:#d5e1ee;font-size:12px}.hero-meta b{color:#fff;margin-right:5px}.toc{display:flex;gap:6px;flex-wrap:wrap;margin:15px 0}.toc a{text-decoration:none;color:#334155;background:rgba(255,255,255,.88);border:1px solid var(--line);border-radius:999px;padding:7px 11px;font-size:12px;font-weight:750;box-shadow:0 4px 14px rgba(15,23,42,.03)}.toc a:hover{background:#fff;color:var(--blue);border-color:#cbd8e8}.section{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:var(--radius);padding:23px;margin:14px 0;box-shadow:var(--shadow)}.section.prominent{padding:26px}.section-head{justify-content:space-between;gap:16px;margin-bottom:12px}.kicker{color:#64748b}.section h2{font-size:23px;letter-spacing:-.03em;margin:0}.section h3.subhead{font-size:15px;margin:22px 0 9px}.section h4{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin:0 0 5px}.section-intro,.note{color:var(--muted);margin:0 0 15px}.section-count{background:#eef2ff;color:#3730a3;border-radius:999px;padding:4px 10px;font-weight:800}.risk-banner{display:flex;gap:12px;border-radius:14px;padding:14px 16px;margin:13px 0 16px;border:1px solid var(--line);background:var(--soft)}.risk-banner strong,.risk-banner span{display:block}.risk-banner span{font-size:12px;color:var(--muted);margin-top:3px}.risk-icon{width:11px;height:11px;border-radius:50%;margin-top:6px;flex:0 0 auto}.risk-banner.ok{background:#f0fdf4;border-color:#bbf7d0}.risk-banner.ok .risk-icon{background:var(--green)}.risk-banner.low{background:#eff6ff;border-color:#bfdbfe}.risk-banner.low .risk-icon{background:var(--blue)}.risk-banner.medium{background:#fffbeb;border-color:#fde68a}.risk-banner.medium .risk-icon{background:var(--amber)}.risk-banner.high,.risk-banner.critical{background:#fff1f2;border-color:#fecdd3}.risk-banner.high .risk-icon{background:var(--red)}.risk-banner.critical .risk-icon{background:var(--red2);box-shadow:0 0 0 4px #fee2e2}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:9px}.metric{background:linear-gradient(180deg,#f8fafc,#f3f6f9);border:1px solid var(--line);border-radius:13px;padding:11px 12px}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;font-size:24px;letter-spacing:-.045em;margin-top:2px}.metric.critical strong{color:var(--red2)}.metric.high strong{color:var(--red)}.metric.medium strong{color:#b45309}.summary-copy{margin-top:18px;max-width:930px}.summary-copy p{margin:8px 0}.coverage-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}.coverage-card{border:1px solid var(--line);background:linear-gradient(180deg,#fbfdff,#f5f8fb);border-radius:13px;padding:13px}.coverage-card span,.coverage-card strong,.coverage-card small{display:block}.coverage-card span{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.055em}.coverage-card strong{font-size:17px;margin:3px 0 4px}.coverage-card small{color:#748196;line-height:1.4}.notice,.context-note{border:1px solid #bae6fd;border-left:4px solid #0ea5e9;background:#f0f9ff;border-radius:12px;padding:12px 14px;margin-top:12px;color:#365269}.finding-list{display:grid;gap:11px}.finding{border:1px solid var(--line);border-left:5px solid #94a3b8;border-radius:15px;padding:17px 18px;background:#fff;box-shadow:0 5px 20px rgba(15,23,42,.025)}.finding.severity-critical{border-left-color:var(--red2)}.finding.severity-high{border-left-color:var(--red)}.finding.severity-medium{border-left-color:#d97706}.finding.severity-low{border-left-color:#0284c7}.finding.severity-info{border-left-color:#64748b}.finding-head{gap:7px;flex-wrap:wrap}.severity-badge,.status-badge{display:inline-flex;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.04em}.severity-badge.severity-critical{background:#fee2e2;color:#7f1d1d}.severity-badge.severity-high{background:#ffe4e6;color:#9f1239}.severity-badge.severity-medium{background:#fef3c7;color:#92400e}.severity-badge.severity-low{background:#e0f2fe;color:#075985}.severity-badge.severity-info{background:#e2e8f0;color:#475569}.status-badge{background:#f1f5f9;color:#475569}.confidence{font-size:11px;color:var(--muted);margin-left:auto}.rule-id{font:11px ui-monospace,SFMono-Regular,Consolas,monospace;color:#64748b;margin:0 0 11px}.finding-target{gap:7px 18px;flex-wrap:wrap;background:#f8fafc;border-radius:9px;padding:8px 10px;font-size:12px;margin:8px 0 13px}.finding-block{margin:11px 0}.finding-block p{margin:0}.finding-block.action{background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:11px 12px}.finding-evidence{font-size:11px;color:#64748b;margin-top:9px}.recommendations{list-style:none;padding:0;margin:0;display:grid;gap:9px}.recommendation{display:grid;grid-template-columns:36px 1fr;gap:11px;padding:14px;border:1px solid var(--line);border-radius:13px;background:#fbfdff}.rec-number{width:31px;height:31px;border-radius:9px;display:grid;place-items:center;background:#e8eef8;color:#334155;font-weight:850}.rec-title{gap:7px}.recommendation p{margin:5px 0}.recommendation small{color:var(--muted)}.severity-dot{width:8px;height:8px;border-radius:50%;background:#94a3b8}.severity-dot.severity-critical{background:var(--red2)}.severity-dot.severity-high{background:var(--red)}.severity-dot.severity-medium{background:#d97706}.severity-dot.severity-low{background:#0284c7}.detail-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}.detail-grid>div{border:1px solid var(--line);background:var(--soft);border-radius:11px;padding:11px}.detail-grid>div.wide{grid-column:span 2}.detail-grid span{display:block;color:var(--muted);font-size:11px}.detail-grid strong{display:block;margin-top:3px;overflow-wrap:anywhere}.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}.chip{background:#eef2ff;border:1px solid #dbe2ff;border-radius:999px;padding:5px 9px}.chip.sensor{background:#effaf8;border-color:#c5eee7;color:#17645a;font-size:11px}.sensor-row{margin-top:14px}.sensor-label{font-size:11px;color:var(--muted);font-weight:700}.runline{gap:8px 22px;flex-wrap:wrap;margin-top:14px;padding:10px 12px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}.runline b{color:#334155}.protocol-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:13px}.protocol-card{border:1px solid var(--line);background:#fbfdff;border-radius:13px;padding:13px}.protocol-title{justify-content:space-between;gap:10px;margin-bottom:8px}.protocol-title span{font-weight:850}.protocol-title strong{font-size:11px;color:#475569;background:#eef2f7;border-radius:999px;padding:4px 8px}.protocol-card dl{display:grid;grid-template-columns:120px 1fr;gap:5px 10px;margin:0}.protocol-card dt{color:var(--muted)}.protocol-card dd{margin:0;overflow-wrap:anywhere}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;font-size:12px}th{background:#f7f9fc;color:#64748b;text-transform:uppercase;letter-spacing:.04em;font-size:10px;position:sticky;top:0}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#fbfdff}td small{display:block;color:#94a3b8;font:10px ui-monospace,monospace;margin-top:2px}.compact-table{max-width:540px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.hash{max-width:260px;overflow-wrap:anywhere}.empty{background:#f8fafc;border:1px dashed #cbd5e1;border-radius:12px;padding:14px;color:var(--muted)}.empty.success{background:#f0fdf4;border-color:#bbf7d0;color:#166534}.empty.success strong,.empty.success span{display:block}.empty.success span{margin-top:4px;font-size:12px;color:#4b6b55}details{border:1px solid var(--line);border-radius:11px;margin:8px 0;background:#fbfdff}summary{cursor:pointer;padding:11px 13px;font-weight:750}details>p,details>ul,details>.table-wrap,details>dl,details>pre{margin:0 13px 13px}.technical pre,.technical-section pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0f172a;color:#dbeafe;border-radius:9px;padding:10px;font-size:11px}.metadata{display:grid;grid-template-columns:190px 1fr;gap:6px 12px}.metadata dt{color:var(--muted)}.metadata dd{margin:0;overflow-wrap:anywhere}footer{justify-content:space-between;gap:16px;flex-wrap:wrap;color:#64748b;font-size:11px;padding:16px 4px 24px}footer div span{display:block}footer strong{color:#334155;font-size:13px}@media(max-width:900px){.page{padding:14px}.hero{padding:21px}.hero h1{font-size:28px}.coverage-grid{grid-template-columns:repeat(2,1fr)}.detail-grid{grid-template-columns:repeat(2,1fr)}.confidence{margin-left:0;width:100%}}@media(max-width:560px){.page{padding:8px}.hero,.section{border-radius:15px}.hero{padding:17px}.hero h1{font-size:23px}.report-version{display:none}.brand-mark{width:33px;height:33px}.coverage-grid,.detail-grid,.protocol-grid{grid-template-columns:1fr}.detail-grid>div.wide{grid-column:auto}.toc{position:sticky;top:0;z-index:3;background:#eef3f8;padding:7px 0;margin:6px 0}.section{padding:16px}.finding{padding:14px}.metadata{grid-template-columns:1fr}.metadata dd{margin-bottom:5px}.protocol-card dl{grid-template-columns:90px 1fr}}@media print{body{background:#fff}.page{max-width:none;padding:0}.hero{box-shadow:none;border-radius:0;print-color-adjust:exact;-webkit-print-color-adjust:exact}.toc{display:none}.section{box-shadow:none;break-inside:auto}.finding,.recommendation,.coverage-card,.protocol-card{break-inside:avoid}.technical-section details{break-inside:auto}a{color:inherit}.table-wrap{overflow:visible}th{position:static}footer{border-top:1px solid var(--line)}}
"""


__all__ = ["render_html"]
