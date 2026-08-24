"""Self-contained HTML renderer for the audit-report view model.

Every interpolated value is HTML-escaped. Raw provider output is never
included. The document carries inline CSS so it can be opened offline.
"""

from __future__ import annotations

import html
import json
from typing import Any

from reports.models import (
    AuditReport,
    ReportAsset,
    ReportEvidenceReference,
    ReportFinding,
    ReportRecommendation,
    ReportService,
)


def render_html(report: AuditReport) -> str:
    document = report.to_document()
    summary = report.executive_summary
    generated = _t(document["generated_at"])
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ru">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_l('report_title')} {_t(report.audit.id)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<header class="hero">\n'
        f"<p class=\"eyebrow\">{_l('eyebrow')}</p>\n"
        f"<h1>{_t(_headline(summary.headline))}</h1>\n"
        "<p class=\"meta\">"
        f"{_l('audit')} {_t(report.audit.id)} · {_l('generated')} {generated} · "
        f"{_l('schema')} {_t(report.schema_name)} v{_t(report.schema_version)}"
        "</p>\n"
        "</header>\n"
        f"{_summary_section(report)}"
        f"{_environment_section(report)}"
        f"{_scope_section(report)}"
        f"{_assets_section(report.assets)}"
        f"{_services_section(report.services)}"
        f"{_findings_section(report.findings)}"
        f"{_recommendations_section(report.recommendations)}"
        f"{_evidence_section(report.evidence_references)}"
        f"{_metadata_section(report)}"
        "</body>\n"
        "</html>\n"
    )


def _summary_section(report: AuditReport) -> str:
    summary = report.executive_summary
    severity_cells = "".join(
        (
            "<div class=\"stat\">"
            f"<span class=\"label\">{_l(f'severity.{name}')}</span>"
            f"<span class=\"value severity-{_t(name)}\">{_t(total)}</span>"
            "</div>"
        )
        for name, total in summary.by_severity.items()
    )
    sensors = (
        ", ".join(_t(name) for name in summary.detected_sensors)
        if summary.detected_sensors
        else _l("none_recorded")
    )
    confirmed = _l("yes") if summary.confirmed_scope else _l("no")
    return (
        '<section id="executive-summary">\n'
        f"<h2>{_l('executive_summary')}</h2>\n"
        '<div class="stats">\n'
        f"<div class=\"stat\"><span class=\"label\">{_l('assets')}</span>"
        f"<span class=\"value\">{_t(summary.asset_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">{_l('services')}</span>"
        f"<span class=\"value\">{_t(summary.service_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">{_l('findings')}</span>"
        f"<span class=\"value\">{_t(summary.finding_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">{_l('open')}</span>"
        f"<span class=\"value\">{_t(summary.open_finding_count)}</span></div>\n"
        "</div>\n"
        f'<div class="stats">{severity_cells}</div>\n'
        f"<p>{_l('confirmed_scope')}: {confirmed}. "
        f"{_l('detected_sensors')}: {sensors}.</p>\n"
        "</section>\n"
    )


def _environment_section(report: AuditReport) -> str:
    env = report.environment
    rows = []
    for iface in env.interfaces:
        addresses = ", ".join(_t(item) for item in [*iface.ipv4, *iface.ipv6])
        rows.append(
            "<tr>"
            f"<td>{_t(iface.name)}</td>"
            f"<td>{_t(iface.state)}</td>"
            f"<td>{_t(iface.mac)}</td>"
            f"<td>{addresses or '—'}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr>"
        f"<th>{_l('interface')}</th><th>{_l('state')}</th>"
        f"<th>MAC</th><th>{_l('addresses')}</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else f"<p>{_l('no_interfaces')}</p>"
    )
    route = env.default_route or {}
    route_text = (
        f"{_l('gateway')} {_t(route.get('gateway'))} "
        f"{_l('via')} {_t(route.get('interface'))}"
        if route
        else _l("not_recorded")
    )
    dns = ", ".join(_t(item) for item in env.dns) or _l("not_recorded")
    hostname = _t(env.hostname) or _l("not_recorded")
    return (
        '<section id="environment">\n'
        f"<h2>{_l('environment')}</h2>\n"
        f"<p>{_l('hostname')}: {hostname}. "
        f"{_l('default_route')}: {route_text}. DNS: {dns}.</p>\n"
        f"{table}\n"
        "</section>\n"
    )


def _scope_section(report: AuditReport) -> str:
    scope = report.scope
    targets = ", ".join(_t(item) for item in scope.targets) or _l("none")
    audit_scope = _json_block(scope.audit_scope)
    confirmed = _l("yes") if scope.confirmed else _l("no")
    address_count = (
        _t(scope.address_count) if scope.address_count is not None else "—"
    )
    return (
        '<section id="scope">\n'
        f"<h2>{_l('scope')}</h2>\n"
        "<p>"
        f"{_l('confirmed')}: {confirmed}. "
        f"{_l('profile')}: {_t(scope.profile) or '—'}. "
        f"{_l('interface')}: {_t(scope.interface) or '—'}. "
        f"{_l('address_count')}: {address_count}. "
        f"{_l('timing')}: {_t(scope.timing_policy) or '—'}."
        "</p>\n"
        f"<p>{_l('targets')}: {targets}.</p>\n"
        f"<h3>{_l('audit_scope_snapshot')}</h3>\n"
        f"{audit_scope}\n"
        "</section>\n"
    )


def _assets_section(assets: list[ReportAsset]) -> str:
    if not assets:
        body = f"<p>{_l('no_assets')}</p>"
    else:
        rows = []
        for asset in assets:
            rows.append(
                "<tr>"
                f"<td>{_t(asset.id)}</td>"
                f"<td>{_t(asset.state)}</td>"
                f"<td>{_t(asset.mac)}</td>"
                f"<td>{_t(asset.vendor)}</td>"
                f"<td>{_t(', '.join(asset.addresses))}</td>"
                f"<td>{_t(', '.join(asset.names))}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>ID</th>"
            f"<th>{_l('state')}</th><th>MAC</th>"
            f"<th>{_l('vendor')}</th><th>{_l('addresses')}</th>"
            f"<th>{_l('names')}</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="assets">\n'
        f"<h2>{_l('assets')}</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _services_section(services: list[ReportService]) -> str:
    if not services:
        body = f"<p>{_l('no_services')}</p>"
    else:
        rows = []
        for service in services:
            product = " ".join(
                part
                for part in (service.product, service.version)
                if part
            )
            rows.append(
                "<tr>"
                f"<td>{_t(service.asset_id)}</td>"
                f"<td>{_t(service.protocol)}</td>"
                f"<td>{_t(service.port)}</td>"
                f"<td>{_t(service.state)}</td>"
                f"<td>{_t(service.service_name)}</td>"
                f"<td>{_t(product)}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr>"
            f"<th>{_l('asset')}</th><th>{_l('proto')}</th><th>{_l('port')}</th>"
            f"<th>{_l('state')}</th><th>{_l('service')}</th>"
            f"<th>{_l('product')}</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="services">\n'
        f"<h2>{_l('services')}</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _findings_section(findings: list[ReportFinding]) -> str:
    if not findings:
        body = f"<p>{_l('no_findings')}</p>"
    else:
        cards = []
        for item in findings:
            cards.append(
                f'<article class="finding severity-{_t(item.severity)}">'
                f"<h3>{_t(item.title)}</h3>"
                "<p class=\"meta\">"
                f"{_t(item.rule_id)} · {_t(item.severity)} · "
                f"{_t(item.status)} · {_l('confidence')} {_t(item.confidence)}"
                "</p>"
                f"<p>{_t(item.description)}</p>"
                f"<p><strong>{_l('rationale')}.</strong> {_t(item.rationale)}</p>"
                f"<p><strong>{_l('recommendation')}.</strong> "
                f"{_t(item.recommendation)}</p>"
                "<p class=\"meta\">"
                f"{_l('asset')} {_t(item.asset_id) or '—'} · "
                f"{_l('service')} {_t(item.service_id) or '—'} · "
                f"{_l('observations')} {len(item.observation_ids)} · "
                f"{_l('evidence')} {len(item.evidence_artifact_ids)}"
                "</p>"
                f"{_json_block(item.data) if item.data else ''}"
                "</article>"
            )
        body = "".join(cards)
    return (
        '<section id="findings">\n'
        f"<h2>{_l('findings')}</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _recommendations_section(
    recommendations: list[ReportRecommendation],
) -> str:
    if not recommendations:
        body = f"<p>{_l('no_recommendations')}</p>"
    else:
        items = []
        for item in recommendations:
            items.append(
                "<li>"
                f"<strong>{_t(item.title)}</strong> "
                f"({_t(item.rule_id)}, {_t(item.severity)}): "
                f"{_t(item.recommendation)} "
                f"— {_t(len(item.finding_ids))} {_l('finding_count')}"
                "</li>"
            )
        body = "<ol>" + "".join(items) + "</ol>"
    return (
        '<section id="recommendations">\n'
        f"<h2>{_l('recommendations')}</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _evidence_section(references: list[ReportEvidenceReference]) -> str:
    note = f"<p>{_l('evidence_note')}</p>"
    if not references:
        body = f"<p>{_l('no_evidence')}</p>"
    else:
        rows = []
        for item in references:
            rows.append(
                "<tr>"
                f"<td>{_t(item.id)}</td>"
                f"<td>{_t(item.artifact_type)}</td>"
                f"<td>{_t(item.content_type)}</td>"
                f"<td>{_t(item.size)}</td>"
                f"<td class=\"hash\">{_t(item.sha256)}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>ID</th>"
            f"<th>{_l('type')}</th><th>{_l('content_type')}</th>"
            f"<th>{_l('size')}</th><th>SHA-256</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="evidence">\n'
        f"<h2>{_l('evidence_references')}</h2>\n"
        f"{note}\n"
        f"{body}\n"
        "</section>\n"
    )


def _metadata_section(report: AuditReport) -> str:
    meta = report.metadata
    warnings = (
        "<ul>"
        + "".join(f"<li>{_t(item)}</li>" for item in meta.warnings)
        + "</ul>"
        if meta.warnings
        else f"<p>{_l('none_period')}</p>"
    )
    excluded = _l("yes") if meta.raw_provider_output_excluded else _l("no")
    truncated = _l("yes") if meta.truncated else _l("no")
    return (
        '<section id="audit-metadata">\n'
        f"<h2>{_l('audit_metadata')}</h2>\n"
        "<ul>\n"
        f"<li>{_l('product')}: {_t(meta.product)} {_t(meta.version)}</li>\n"
        f"<li>{_l('report_id')}: {_t(report.report_id)}</li>\n"
        f"<li>{_l('source_hash')}: {_t(report.source_hash)}</li>\n"
        f"<li>{_l('job_id')}: {_t(meta.job_id) or '—'}</li>\n"
        f"<li>{_l('actor')}: {_t(meta.actor) or '—'}</li>\n"
        f"<li>{_l('audit_status')}: {_t(report.audit.status)}</li>\n"
        f"<li>{_l('audit_profile')}: {_t(report.audit.profile)}</li>\n"
        f"<li>{_l('raw_excluded')}: {excluded}</li>\n"
        f"<li>{_l('truncated')}: {truncated}</li>\n"
        "</ul>\n"
        f"<h3>{_l('warnings')}</h3>\n"
        f"{warnings}\n"
        "</section>\n"
    )


def _json_block(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )
    return f"<pre>{_t(encoded)}</pre>"


def _t(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _l(key: str) -> str:
    return html.escape(_LABELS.get(key, key), quote=True)


def _headline(text: str) -> str:
    return _HEADLINES.get(text, text)


_LABELS = {
    "report_title": "Отчёт WireScope",
    "eyebrow": "Отчёт аудита WireScope",
    "audit": "Аудит",
    "generated": "сформирован",
    "schema": "схема",
    "executive_summary": "Краткое резюме",
    "assets": "Активы",
    "services": "Службы",
    "findings": "Находки",
    "open": "Открытые",
    "confirmed_scope": "Уполномоченная область",
    "detected_sensors": "Обнаруженные пассивные датчики",
    "none_recorded": "не зафиксировано",
    "yes": "да",
    "no": "нет",
    "environment": "Окружение",
    "hostname": "Имя хоста",
    "default_route": "Маршрут по умолчанию",
    "gateway": "шлюз",
    "via": "через",
    "not_recorded": "не зафиксировано",
    "interface": "Интерфейс",
    "state": "Состояние",
    "addresses": "Адреса",
    "no_interfaces": "Снимок интерфейсов не сохранён.",
    "scope": "Область",
    "confirmed": "Подтверждена",
    "profile": "Профиль",
    "address_count": "Число адресов",
    "timing": "Тайминг",
    "targets": "Цели",
    "none": "нет",
    "none_period": "Нет.",
    "audit_scope_snapshot": "Снимок области аудита",
    "no_assets": "Для этого аудита активы не сохранены.",
    "vendor": "Производитель",
    "names": "Имена",
    "no_services": "Для этого аудита службы не сохранены.",
    "asset": "Актив",
    "proto": "Протокол",
    "port": "Порт",
    "service": "Служба",
    "product": "Продукт",
    "no_findings": "Для этого аудита находки не сохранены.",
    "confidence": "уверенность",
    "rationale": "Обоснование",
    "recommendation": "Рекомендация",
    "observations": "наблюдения",
    "evidence": "доказательства",
    "recommendations": "Рекомендации",
    "no_recommendations": "Рекомендаций по открытым находкам нет.",
    "finding_count": "находка(и)",
    "evidence_note": (
        "Сырой вывод инструментов остаётся в контролируемом хранилище. "
        "В отчёте только идентификаторы, типы, размеры и SHA-256."
    ),
    "no_evidence": "Артефакты доказательств не указаны.",
    "evidence_references": "Ссылки на доказательства",
    "type": "Тип",
    "content_type": "Тип содержимого",
    "size": "Размер",
    "audit_metadata": "Метаданные аудита",
    "product": "Продукт",
    "report_id": "ID отчёта",
    "source_hash": "Хеш источника",
    "job_id": "ID задания",
    "actor": "Исполнитель",
    "audit_status": "Статус аудита",
    "audit_profile": "Профиль аудита",
    "raw_excluded": "Сырой вывод инструментов исключён",
    "truncated": "Усечено",
    "warnings": "Предупреждения",
    "severity.critical": "критическая",
    "severity.high": "высокая",
    "severity.medium": "средняя",
    "severity.low": "низкая",
    "severity.info": "инфо",
}

_HEADLINES = {
    "Open critical findings require attention": (
        "Открытые критические находки требуют внимания"
    ),
    "Open high-severity findings were identified": (
        "Выявлены открытые находки высокой серьёзности"
    ),
    "Open medium-severity findings were identified": (
        "Выявлены открытые находки средней серьёзности"
    ),
    "Open findings were recorded": "Зафиксированы открытые находки",
    "No open findings were recorded for the confirmed scope": (
        "По подтверждённой области открытых находок нет"
    ),
    "No open findings were recorded": "Открытых находок не зафиксировано",
}


_CSS = """
:root { color-scheme: light; }
html { font-size: 16px; }
body {
  margin: 0 auto;
  max-width: 60rem;
  padding: 1rem;
  font-family: system-ui, sans-serif;
  line-height: 1.45;
  color: #1b1b1b;
  background: #f7f5f2;
}
.hero, section {
  background: #fff;
  border: 1px solid #d9d4cc;
  border-radius: 0.5rem;
  padding: 1rem;
  margin-bottom: 1rem;
}
h1, h2, h3 { line-height: 1.2; }
h1 { font-size: 1.6rem; margin: 0.2rem 0 0.6rem; }
h2 { font-size: 1.2rem; margin-top: 0; }
.eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.75rem; }
.meta { color: #4a4a4a; font-size: 0.9rem; }
.stats { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.75rem 0; }
.stat {
  min-width: 5.5rem;
  background: #f0ece6;
  border-radius: 0.4rem;
  padding: 0.5rem 0.7rem;
}
.stat .label { display: block; font-size: 0.75rem; color: #5c5c5c; }
.stat .value { font-size: 1.2rem; font-weight: 650; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { border-bottom: 1px solid #e6e1da; text-align: left; padding: 0.35rem; vertical-align: top; }
.hash, pre { overflow-wrap: anywhere; word-break: break-word; }
pre {
  background: #f4f1ec;
  padding: 0.6rem;
  border-radius: 0.35rem;
  font-size: 0.8rem;
}
.finding { border-left: 0.35rem solid #5d6d7e; padding-left: 0.7rem; margin: 0.8rem 0; }
.severity-critical, .finding.severity-critical { border-color: #8b1a1a; color: inherit; }
.severity-high, .finding.severity-high { border-color: #c0392b; }
.severity-medium, .finding.severity-medium { border-color: #d68910; }
.severity-low, .finding.severity-low { border-color: #1f618d; }
.stat .value.severity-critical { color: #8b1a1a; }
.stat .value.severity-high { color: #c0392b; }
@media (max-width: 40rem) {
  body { padding: 0.6rem; }
  table { display: block; overflow-x: auto; }
  h1 { font-size: 1.3rem; }
}
""".replace("\n", "")
