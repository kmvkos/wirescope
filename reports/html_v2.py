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


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_RU = {
    "severity": {
        "critical": "Критическая",
        "high": "Высокая",
        "medium": "Средняя",
        "low": "Низкая",
        "info": "Информационная",
    },
    "status": {
        "open": "Открыта",
        "suppressed": "Подавлена",
        "accepted_risk": "Риск принят",
        "completed": "Завершён",
        "failed": "Ошибка",
        "running": "Выполняется",
        "queued": "В очереди",
        "cancelled": "Отменён",
        "interrupted": "Прерван",
        "responsive": "Отвечает",
        "unresponsive": "Не отвечает",
        "observed": "Наблюдался",
        "unknown": "Не определено",
        "open": "Открыт",
        "closed": "Закрыт",
        "filtered": "Фильтруется",
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
        "unknown": "Не определено",
    },
    "visibility": {
        "local": "Локальная видимость",
        "broadcast": "В основном широковещательный трафик",
        "limited": "Ограниченная видимость",
        "unknown": "Не определена",
    },
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
            "<details class=\"technical\"><summary>Технические данные правила</summary>"
            f"<pre>{_e(encoded)}</pre></details>"
        )
    return (
        f'<article class="finding severity-{_e(item.severity)}">'
        '<div class="finding-head">'
        f'<span class="severity-badge severity-{_e(item.severity)}">{_ru("severity", item.severity)}</span>'
        f'<span class="status-badge">{_ru("status", item.status)}</span>'
        f'<span class="confidence">Уверенность: {_ru("confidence", item.confidence)}</span>'
        "</div>"
        f"<h3>{_e(item.title)}</h3>"
        f'<p class="rule-id">Правило {_e(item.rule_id)}</p>'
        f'<div class="finding-target">{target}</div>'
        f'<div class="finding-block"><h4>Что обнаружено</h4><p>{_e(item.description)}</p></div>'
        f'<div class="finding-block"><h4>Почему это важно</h4><p>{_e(item.rationale)}</p></div>'
        f'<div class="finding-block action"><h4>Что рекомендуется сделать</h4><p>{_e(item.recommendation)}</p></div>'
        f"{data}"
        "</article>"
    )


def render_html(report: AuditReport) -> str:
    summary = report.executive_summary
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
            f'<div class="metric"><span>Проблемы</span><strong>{summary.finding_count}</strong></div>',
            f'<div class="metric"><span>Открытые</span><strong>{summary.open_finding_count}</strong></div>',
            f'<div class="metric critical"><span>Критические</span><strong>{by_severity.get("critical", 0)}</strong></div>',
            f'<div class="metric high"><span>Высокие</span><strong>{by_severity.get("high", 0)}</strong></div>',
        ]
    )

    targets = "".join(f'<span class="chip mono">{_e(item)}</span>' for item in report.scope.targets)
    if not targets:
        targets = '<span class="muted">Цели не сохранены</span>'

    asset_rows = []
    for asset in report.assets:
        label = ", ".join(asset.names[:2] or asset.addresses[:2]) or asset.id
        addresses = ", ".join(asset.addresses) or "—"
        asset_rows.append(
            "<tr>"
            f"<td><strong>{_e(label)}</strong><small>{_e(asset.id)}</small></td>"
            f"<td>{_e(addresses)}</td>"
            f"<td>{_e(asset.mac)}</td>"
            f"<td>{_e(asset.vendor)}</td>"
            f"<td>{_ru('device_class', asset.device_class_hint)}</td>"
            f"<td>{_e(asset.os_name)}</td>"
            "</tr>"
        )
    assets = (
        '<div class="table-wrap"><table><thead><tr><th>Устройство</th><th>Адреса</th><th>MAC</th>'
        '<th>Производитель</th><th>Тип</th><th>ОС</th></tr></thead><tbody>'
        + "".join(asset_rows)
        + "</tbody></table></div>"
        if asset_rows else '<p class="empty">Устройства для этого аудита не сохранены.</p>'
    )

    service_rows = []
    for service in report.services:
        product = " ".join(x for x in (service.product, service.version) if x) or "—"
        service_rows.append(
            "<tr>"
            f"<td class=\"mono\">{_e(service.asset_id)}</td>"
            f"<td><strong>{_e(service.port)}/{_e(service.protocol)}</strong></td>"
            f"<td>{_e(service.service_name)}</td>"
            f"<td>{_e(product)}</td>"
            f"<td>{_ru('status', service.state)}</td>"
            "</tr>"
        )
    services = (
        '<div class="table-wrap"><table><thead><tr><th>Устройство</th><th>Порт</th><th>Служба</th>'
        '<th>Продукт / версия</th><th>Состояние</th></tr></thead><tbody>'
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
            f'<div class="rec-title"><span class="severity-dot severity-{_e(item.severity)}"></span>'
            f'<strong>{_e(item.title)}</strong></div>'
            f'<p>{_e(item.recommendation)}</p>'
            f'<small>{_count(len(item.finding_ids), "связанная проблема", "связанные проблемы", "связанных проблем")}</small>'
            '</div></li>'
        )
    recommendations = "".join(recs) or '<p class="empty">Отдельных рекомендаций по открытым проблемам нет.</p>'

    passive = report.passive
    vlan_text = ", ".join(str(item) for item in passive.tagged_vlan_ids) or "Не обнаружены"
    passive_details = (
        '<div class="detail-grid">'
        f'<div><span>Интерфейс</span><strong>{_e(passive.capture_interface)}</strong></div>'
        f'<div><span>Кадры</span><strong>{_e(passive.frame_count)}</strong></div>'
        f'<div><span>Состояние сегмента</span><strong>{_ru("segment", passive.segment_status)}</strong></div>'
        f'<div><span>Видимость</span><strong>{_ru("visibility", passive.visibility)}</strong></div>'
        f'<div><span>VLAN с тегом 802.1Q</span><strong>{_e(vlan_text)}</strong></div>'
        f'<div><span>ARP-узлы</span><strong>{passive.arp_host_count}</strong></div>'
        '</div>'
    )

    evidence_rows = []
    for item in report.evidence_references:
        evidence_rows.append(
            "<tr>"
            f'<td class="mono">{_e(item.id)}</td><td>{_e(item.artifact_type)}</td>'
            f'<td>{_e(item.content_type)}</td><td>{_e(_bytes(item.size))}</td>'
            f'<td class="mono hash">{_e(item.sha256)}</td>'
            "</tr>"
        )
    evidence = (
        '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Тип</th><th>Формат</th><th>Размер</th><th>SHA-256</th></tr></thead><tbody>'
        + "".join(evidence_rows) + "</tbody></table></div>"
        if evidence_rows else '<p class="empty">Артефакты доказательств не зарегистрированы.</p>'
    )

    warnings = "".join(f"<li>{_e(item)}</li>" for item in report.metadata.warnings) or "<li>Нет</li>"
    scope_confirmed = "Да" if report.scope.confirmed else "Нет"
    l3 = "Да" if passive.had_l3_address is True else "Нет" if passive.had_l3_address is False else "Не определено"

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
  <div class="brand-row"><div><span class="brand">WireScope</span><span class="brand-sub">Отчёт сетевого аудита</span></div><span class="report-version">audit-report v{report.schema_version}</span></div>
  <div class="hero-main"><div><p class="eyebrow">Итог аудита</p><h1>{_e(summary.headline)}</h1><p class="hero-copy">Отчёт сформирован из сохранённых результатов WireScope. Повторное сканирование при формировании отчёта не выполнялось.</p></div></div>
  <div class="hero-meta"><span><b>Аудит</b> {_e(report.audit.id)}</span><span><b>Профиль</b> {_ru('profile', report.audit.profile)}</span><span><b>Интерфейс</b> {_e(report.audit.interface)}</span><span><b>Сформирован</b> {_date(report.generated_at)}</span></div>
</header>

<nav class="toc" aria-label="Разделы отчёта">
<a href="#executive-summary">Итог</a><a href="#findings">Проблемы</a><a href="#recommendations">Что делать</a><a href="#assets">Устройства</a><a href="#services">Службы</a><a href="#technical">Технические данные</a>
</nav>

<main>
<section id="executive-summary" class="section prominent">
  <div class="section-head"><div><p class="kicker">Главное</p><h2>Результат аудита</h2></div></div>
  <div class="risk-banner {risk_class}"><span class="risk-icon"></span><div><strong>{_e(risk_text)}</strong><span>Приоритет определяется по открытым findings и только в пределах выполненного scope.</span></div></div>
  <div class="metrics">{stats}</div>
  <div class="summary-copy">{_paragraphs(summary.summary)}</div>
</section>

<section id="findings" class="section">
  <div class="section-head"><div><p class="kicker">Безопасность</p><h2>Обнаруженные проблемы</h2></div><span class="section-count">{len(findings)}</span></div>
  <p class="section-intro">Каждая запись ниже объясняет, что именно обнаружено, почему это имеет значение и что рекомендуется сделать.</p>
  <div class="finding-list">{finding_html}</div>
</section>

<section id="recommendations" class="section">
  <div class="section-head"><div><p class="kicker">План действий</p><h2>Рекомендации</h2></div></div>
  <p class="section-intro">Начинайте с критических и высоких проблем. После исправления повторите аудит и сравните результаты.</p>
  <ol class="recommendations">{recommendations}</ol>
</section>

<section id="scope" class="section">
  <div class="section-head"><div><p class="kicker">Границы проверки</p><h2>Scope аудита</h2></div></div>
  <div class="detail-grid">
    <div><span>Подтверждён оператором</span><strong>{scope_confirmed}</strong></div>
    <div><span>Профиль</span><strong>{_ru('profile', report.scope.profile)}</strong></div>
    <div><span>Интерфейс</span><strong>{_e(report.scope.interface)}</strong></div>
    <div><span>Адресов в scope</span><strong>{_e(report.scope.address_count)}</strong></div>
  </div>
  <div class="chips">{targets}</div>
</section>

<section id="assets" class="section">
  <div class="section-head"><div><p class="kicker">Инвентаризация</p><h2>Устройства</h2></div><span class="section-count">{len(report.assets)}</span></div>
  {assets}
</section>

<section id="services" class="section">
  <div class="section-head"><div><p class="kicker">Поверхность сети</p><h2>Обнаруженные службы</h2></div><span class="section-count">{len(report.services)}</span></div>
  {services}
</section>

<section id="passive" class="section">
  <div class="section-head"><div><p class="kicker">Пассивное наблюдение</p><h2>Что было видно в сегменте</h2></div></div>
  {passive_details}
  <p class="note">L3-адрес на интерфейсе захвата: <strong>{l3}</strong>. VLAN ID считается наблюдаемым только при наличии тега 802.1Q в кадре. Нетегированный трафик access-порта не позволяет достоверно определить VLAN ID.</p>
</section>

<section id="technical" class="section technical-section">
  <div class="section-head"><div><p class="kicker">Для проверки и воспроизводимости</p><h2>Технические данные</h2></div></div>
  <details><summary>Evidence / доказательства ({len(report.evidence_references)})</summary><p class="note">Сырой вывод инструментов не встраивается в отчёт. Здесь перечислены зарегистрированные артефакты, их размер и контрольная сумма.</p>{evidence}</details>
  <details><summary>Метаданные отчёта</summary><dl class="metadata"><dt>ID отчёта</dt><dd>{_e(report.report_id)}</dd><dt>Source hash</dt><dd class="mono">{_e(report.source_hash)}</dd><dt>Статус аудита</dt><dd>{_ru('status', report.audit.status)}</dd><dt>Исполнитель</dt><dd>{_e(report.metadata.actor)}</dd><dt>Сырой вывод исключён</dt><dd>{'Да' if report.metadata.raw_provider_output_excluded else 'Нет'}</dd><dt>Данные усечены</dt><dd>{'Да' if report.metadata.truncated else 'Нет'}</dd></dl></details>
  <details><summary>Предупреждения генератора</summary><ul>{warnings}</ul></details>
</section>
</main>

<footer><strong>WireScope</strong><span>Сетевой аудит · отчёт из сохранённых данных</span><span class="mono">{_e(report.source_hash[:16])}</span></footer>
</div>
</body>
</html>
"""


_CSS = r"""
:root{color-scheme:light;--ink:#162033;--muted:#667085;--line:#e3e9f1;--surface:#fff;--soft:#f5f8fb;--navy:#0c1b2e;--blue:#2563eb;--cyan:#0891b2;--green:#15803d;--amber:#b45309;--red:#b42318;--red2:#7f1d1d;--radius:16px;--shadow:0 14px 38px rgba(15,23,42,.08)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#eef3f8;color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}.page{max-width:1180px;margin:auto;padding:28px}.hero{background:linear-gradient(135deg,#0a1729,#102947 66%,#0d4660);color:#fff;border-radius:22px;padding:28px 30px;box-shadow:0 20px 55px rgba(15,23,42,.18)}.brand-row,.hero-meta,.section-head,.finding-head,.finding-target,.rec-title,footer{display:flex;align-items:center}.brand-row{justify-content:space-between;gap:20px}.brand{font-weight:800;font-size:22px;letter-spacing:-.03em}.brand-sub{display:block;color:#b9cbe0;font-size:12px;margin-top:1px}.report-version{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.07);border-radius:999px;padding:6px 10px;font:11px ui-monospace,monospace;color:#dceafb}.hero-main{display:grid;grid-template-columns:1fr;gap:24px;margin:34px 0 24px}.eyebrow,.kicker{margin:0 0 7px;text-transform:uppercase;letter-spacing:.1em;font-size:11px;font-weight:800}.eyebrow{color:#7dd3fc}.hero h1{font-size:34px;line-height:1.12;letter-spacing:-.035em;margin:0;max-width:850px}.hero-copy{color:#c7d6e8;max-width:800px;margin:13px 0 0}.hero-meta{gap:10px 22px;flex-wrap:wrap;color:#d5e1ee;font-size:12px}.hero-meta b{color:#fff;margin-right:5px}.toc{display:flex;gap:6px;flex-wrap:wrap;margin:15px 0}.toc a{text-decoration:none;color:#334155;background:rgba(255,255,255,.84);border:1px solid var(--line);border-radius:999px;padding:7px 11px;font-size:12px;font-weight:700}.toc a:hover{background:#fff;color:var(--blue)}.section{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin:14px 0;box-shadow:var(--shadow)}.section.prominent{padding:25px}.section-head{justify-content:space-between;gap:16px;margin-bottom:12px}.kicker{color:#64748b}.section h2{font-size:22px;letter-spacing:-.025em;margin:0}.section h3{font-size:18px;line-height:1.3;margin:12px 0 4px}.section h4{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#64748b;margin:0 0 5px}.section-intro,.note{color:var(--muted);margin:0 0 15px}.section-count{background:#eef2ff;color:#3730a3;border-radius:999px;padding:4px 10px;font-weight:800}.risk-banner{display:flex;gap:12px;border-radius:13px;padding:14px 16px;margin:13px 0 16px;border:1px solid var(--line);background:var(--soft)}.risk-banner strong,.risk-banner span{display:block}.risk-banner span{font-size:12px;color:var(--muted);margin-top:3px}.risk-icon{width:11px;height:11px;border-radius:50%;margin-top:6px;flex:0 0 auto}.risk-banner.ok{background:#f0fdf4;border-color:#bbf7d0}.risk-banner.ok .risk-icon{background:var(--green)}.risk-banner.low{background:#eff6ff;border-color:#bfdbfe}.risk-banner.low .risk-icon{background:var(--blue)}.risk-banner.medium{background:#fffbeb;border-color:#fde68a}.risk-banner.medium .risk-icon{background:var(--amber)}.risk-banner.high,.risk-banner.critical{background:#fff1f2;border-color:#fecdd3}.risk-banner.high .risk-icon{background:var(--red)}.risk-banner.critical .risk-icon{background:var(--red2);box-shadow:0 0 0 4px #fee2e2}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:9px}.metric{background:var(--soft);border:1px solid var(--line);border-radius:12px;padding:11px 12px}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;font-size:24px;letter-spacing:-.04em;margin-top:2px}.metric.critical strong{color:var(--red2)}.metric.high strong{color:var(--red)}.summary-copy{margin-top:17px;max-width:900px}.summary-copy p{margin:8px 0}.finding-list{display:grid;gap:11px}.finding{border:1px solid var(--line);border-left:5px solid #94a3b8;border-radius:14px;padding:17px 18px;background:#fff}.finding.severity-critical{border-left-color:var(--red2)}.finding.severity-high{border-left-color:var(--red)}.finding.severity-medium{border-left-color:#d97706}.finding.severity-low{border-left-color:#0284c7}.finding.severity-info{border-left-color:#64748b}.finding-head{gap:7px;flex-wrap:wrap}.severity-badge,.status-badge{display:inline-flex;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}.severity-badge.severity-critical{background:#fee2e2;color:#7f1d1d}.severity-badge.severity-high{background:#ffe4e6;color:#9f1239}.severity-badge.severity-medium{background:#fef3c7;color:#92400e}.severity-badge.severity-low{background:#e0f2fe;color:#075985}.severity-badge.severity-info{background:#e2e8f0;color:#475569}.status-badge{background:#f1f5f9;color:#475569}.confidence{font-size:11px;color:var(--muted);margin-left:auto}.rule-id{font:11px ui-monospace,SFMono-Regular,Consolas,monospace;color:#64748b;margin:0 0 11px}.finding-target{gap:7px 18px;flex-wrap:wrap;background:#f8fafc;border-radius:9px;padding:8px 10px;font-size:12px;margin:8px 0 13px}.finding-block{margin:11px 0}.finding-block p{margin:0}.finding-block.action{background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:11px 12px}.recommendations{list-style:none;padding:0;margin:0;display:grid;gap:9px}.recommendation{display:grid;grid-template-columns:34px 1fr;gap:10px;padding:13px;border:1px solid var(--line);border-radius:12px;background:#fbfdff}.rec-number{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:#e8eef8;color:#334155;font-weight:800}.rec-title{gap:7px}.recommendation p{margin:5px 0}.recommendation small{color:var(--muted)}.severity-dot{width:8px;height:8px;border-radius:50%;background:#94a3b8}.severity-dot.severity-critical{background:var(--red2)}.severity-dot.severity-high{background:var(--red)}.severity-dot.severity-medium{background:#d97706}.severity-dot.severity-low{background:#0284c7}.detail-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}.detail-grid>div{border:1px solid var(--line);background:var(--soft);border-radius:11px;padding:11px}.detail-grid span{display:block;color:var(--muted);font-size:11px}.detail-grid strong{display:block;margin-top:3px;overflow-wrap:anywhere}.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}.chip{background:#eef2ff;border:1px solid #dbe2ff;border-radius:999px;padding:5px 9px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;font-size:12px}th{background:#f7f9fc;color:#64748b;text-transform:uppercase;letter-spacing:.04em;font-size:10px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:last-child td{border-bottom:0}td small{display:block;color:#94a3b8;font:10px ui-monospace,monospace;margin-top:2px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.hash{max-width:260px;overflow-wrap:anywhere}.empty{background:#f8fafc;border:1px dashed #cbd5e1;border-radius:12px;padding:14px;color:var(--muted)}.empty.success{background:#f0fdf4;border-color:#bbf7d0;color:#166534}.empty.success strong,.empty.success span{display:block}.empty.success span{margin-top:4px;font-size:12px;color:#4b6b55}details{border:1px solid var(--line);border-radius:11px;margin:8px 0;background:#fbfdff}summary{cursor:pointer;padding:11px 13px;font-weight:700}details>p,details>ul,details>.table-wrap,details>dl,details>pre{margin:0 13px 13px}.technical pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0f172a;color:#dbeafe;border-radius:9px;padding:10px;font-size:11px}.metadata{display:grid;grid-template-columns:180px 1fr;gap:6px 12px}.metadata dt{color:var(--muted)}.metadata dd{margin:0;overflow-wrap:anywhere}footer{justify-content:space-between;gap:16px;flex-wrap:wrap;color:#64748b;font-size:11px;padding:15px 4px 22px}footer strong{color:#334155}@media(max-width:850px){.page{padding:14px}.hero{padding:20px}.hero h1{font-size:27px}.metrics{grid-template-columns:repeat(3,1fr)}.detail-grid{grid-template-columns:repeat(2,1fr)}.confidence{margin-left:0;width:100%}}@media(max-width:520px){.page{padding:8px}.hero,.section{border-radius:14px}.hero{padding:17px}.hero h1{font-size:23px}.report-version{display:none}.metrics{grid-template-columns:repeat(2,1fr)}.detail-grid{grid-template-columns:1fr}.toc{position:sticky;top:0;z-index:3;background:#eef3f8;padding:7px 0;margin:6px 0}.section{padding:16px}.finding{padding:14px}.metadata{grid-template-columns:1fr}.metadata dd{margin-bottom:5px}}@media print{body{background:#fff}.page{max-width:none;padding:0}.hero{box-shadow:none;border-radius:0;print-color-adjust:exact;-webkit-print-color-adjust:exact}.toc{display:none}.section{box-shadow:none;break-inside:avoid}.finding{break-inside:avoid}.technical-section details{break-inside:auto}a{color:inherit}.table-wrap{overflow:visible}footer{border-top:1px solid var(--line)}}
"""


__all__ = ["render_html"]
