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
        f"{_passive_section(report)}"
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
    l3 = _l3_label(summary.had_l3_address)
    vlans = (
        ", ".join(_t(item) for item in summary.tagged_vlan_ids)
        if summary.tagged_vlan_ids
        else _l("no_tagged_vlans")
    )
    frames = (
        _t(summary.frame_count) if summary.frame_count is not None else "—"
    )
    narrative = "".join(
        f"<p class=\"callout\">{_t(paragraph)}</p>\n"
        for paragraph in _summary_paragraphs(summary.summary)
    )
    return (
        '<section id="executive-summary">\n'
        f"<h2>{_l('executive_summary')}</h2>\n"
        f"{narrative}"
        f"<p class=\"hint\">{_t(_segment_note(summary.segment_note))}</p>\n"
        '<div class="stats">\n'
        f"<div class=\"stat\"><span class=\"label\">{_l('frames')}</span>"
        f"<span class=\"value\">{frames}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">{_l('l3_address')}</span>"
        f"<span class=\"value\">{l3}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">{_l('tagged_vlans')}</span>"
        f"<span class=\"value\">{vlans}</span></div>\n"
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
        f"<p class=\"hint\">{_l('vlan_tag_note')}</p>\n"
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
    capture = _t(env.capture_interface) or _l("not_recorded")
    l3 = _l3_label(env.had_l3_address)
    return (
        '<section id="environment">\n'
        f"<h2>{_l('environment')}</h2>\n"
        f"<p><strong>{_l('capture_interface')}</strong>: {capture}. "
        f"<strong>{_l('l3_address')}</strong>: {l3}.</p>\n"
        f"<p>{_l('hostname')}: {hostname}. "
        f"{_l('default_route')}: {route_text}. DNS: {dns}.</p>\n"
        f"{table}\n"
        "</section>\n"
    )


def _passive_section(report: AuditReport) -> str:
    passive = report.passive
    l3 = _l3_label(passive.had_l3_address)
    frames = (
        _t(passive.frame_count) if passive.frame_count is not None else "—"
    )
    duration = (
        _t(passive.duration_seconds)
        if passive.duration_seconds is not None
        else "—"
    )
    vlans = (
        ", ".join(_t(item) for item in passive.tagged_vlan_ids)
        if passive.tagged_vlan_ids
        else _l("no_tagged_vlans")
    )
    visibility = _t(passive.visibility) or _l("not_recorded")
    port_hint = _t(passive.port_type_hint) or _l("not_recorded")
    addresses = ", ".join(
        _t(item) for item in [*passive.capture_ipv4, *passive.capture_ipv6]
    ) or _l("none_recorded")
    neighbor_body = _neighbor_table(passive.neighbors)
    naming_rows = []
    for item in passive.naming:
        names = ", ".join(_t(name) for name in item.names) or "—"
        naming_rows.append(
            "<tr>"
            f"<td>{_t(item.name)}</td>"
            f"<td>{_t(item.status)}</td>"
            f"<td>{_t(item.hits)}</td>"
            f"<td>{names}</td>"
            "</tr>"
        )
    naming_table = (
        "<table><thead><tr>"
        f"<th>{_l('protocol')}</th><th>{_l('state')}</th>"
        f"<th>{_l('hits')}</th><th>{_l('names')}</th>"
        "</tr></thead><tbody>"
        + "".join(naming_rows)
        + "</tbody></table>"
        if naming_rows
        else f"<p>{_l('none_recorded')}</p>"
    )
    arp_text = (
        ", ".join(
            f"{_t(item.get('ipv4'))} ({_t(item.get('mac'))})"
            for item in passive.arp_bindings
        )
        or _l("none_recorded")
    )
    dhcp = passive.dhcp
    dhcp_text = (
        f"{_l('servers')}: "
        + (
            ", ".join(_t(item) for item in dhcp.servers)
            or _l("none_recorded")
        )
        + f". {_l('routers')}: "
        + (
            ", ".join(_t(item) for item in dhcp.routers)
            or _l("none_recorded")
        )
    )
    stp = passive.stp
    stp_roots = (
        ", ".join(_t(item) for item in stp.root_bridge_ids)
        or _l("none_recorded")
    )
    return (
        '<section id="passive">\n'
        f"<h2>{_l('passive')}</h2>\n"
        f"<p class=\"callout\">{_t(_segment_note(passive.segment_note))}</p>\n"
        f"<p class=\"hint\">{_l('vlan_tag_note')}</p>\n"
        "<p>"
        f"{_l('capture_interface')}: {_t(passive.capture_interface) or '—'}. "
        f"{_l('l3_address')}: {l3}. "
        f"{_l('addresses')}: {addresses}."
        "</p>\n"
        "<p>"
        f"{_l('frames')}: {frames}. "
        f"{_l('duration')}: {duration}. "
        f"{_l('visibility')}: {visibility}. "
        f"{_l('port_hint')}: {port_hint}."
        "</p>\n"
        "<p>"
        f"{_l('tagged_vlans')}: {vlans}. "
        f"{_l('tagged_frames')}: {_t(passive.tagged_frame_count)}. "
        f"{_l('untagged')}: "
        f"{_l('yes') if passive.untagged_traffic_observed else _l('no')}."
        "</p>\n"
        f"<h3>{_l('neighbors')}</h3>\n"
        f"{neighbor_body}\n"
        f"<h3>STP</h3>\n"
        f"<p>{_l('stp_bpdus')}: {_t(stp.bpdus_observed)}. "
        f"{_l('stp_root')}: {stp_roots}.</p>\n"
        f"<h3>ARP</h3>\n"
        f"<p>{_l('arp_hosts')}: {_t(passive.arp_host_count)}. {arp_text}.</p>\n"
        f"<h3>DHCP</h3>\n"
        f"<p>{dhcp_text}</p>\n"
        f"<h3>{_l('naming')}</h3>\n"
        f"{naming_table}\n"
        "</section>\n"
    )


def _neighbor_table(neighbors) -> str:
    if not neighbors:
        return f"<p>{_l('no_neighbors')}</p>"
    rows = []
    for item in neighbors:
        vlans = []
        if item.native_vlan is not None:
            vlans.append(f"{_l('native_vlan')} {_t(item.native_vlan)}")
        if item.voice_vlan is not None:
            vlans.append(f"{_l('voice_vlan')} {_t(item.voice_vlan)}")
        if item.pvid is not None:
            vlans.append(f"PVID {_t(item.pvid)}")
        rows.append(
            "<tr>"
            f"<td>{_t(item.protocol)}</td>"
            f"<td>{_t(item.name)}</td>"
            f"<td>{_t(item.port_id)}</td>"
            f"<td>{', '.join(vlans) or '—'}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr>"
        f"<th>{_l('protocol')}</th><th>{_l('neighbor_name')}</th>"
        f"<th>{_l('port')}</th><th>VLAN</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
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
                f"{_t(item.rule_id)} · {_l(f'severity.{item.severity}')} · "
                f"{_l(f'status.{item.status}')} · {_l('confidence')} "
                f"{_l(f'confidence.{item.confidence}')}"
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
                f"({_t(item.rule_id)}, {_l(f'severity.{item.severity}')}): "
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


def _summary_paragraphs(text: str) -> list[str]:
    return [part.strip() for part in text.split("\n\n") if part.strip()]


def _l3_label(value: bool | None) -> str:
    if value is True:
        return _l("yes")
    if value is False:
        return _l("no")
    return _l("not_recorded")


def _segment_note(text: str) -> str:
    if text in _SEGMENT_NOTES:
        return _SEGMENT_NOTES[text]
    return _translate_tagged_note(text) or text


def _headline(text: str) -> str:
    if text in _HEADLINES:
        return _HEADLINES[text]
    translated = _translate_tagged_note(text)
    if translated:
        return translated.rstrip(".")
    return text


_LABELS = {
    "report_title": "Отчёт WireScope",
    "eyebrow": "Отчёт аудита WireScope",
    "audit": "Аудит",
    "generated": "сформирован",
    "schema": "схема",
    "executive_summary": "Выводы",
    "assets": "Устройства",
    "services": "Службы",
    "findings": "Слабые места",
    "open": "Открытые",
    "confirmed_scope": "Подтверждённая сеть",
    "detected_sensors": "Обнаруженные пассивные датчики",
    "none_recorded": "не зафиксировано",
    "yes": "да",
    "no": "нет",
    "frames": "Кадры",
    "l3_address": "L3-адрес на NIC захвата",
    "tagged_vlans": "Тегированные VLAN",
    "no_tagged_vlans": "нет (тегов 802.1Q не видно)",
    "vlan_tag_note": (
        "VLAN в кадре виден только при 802.1Q; access-порт коммутатора часто "
        "без тега — тогда ID неизвестен, но трафик этой сети всё равно виден"
    ),
    "environment": "Окружение",
    "capture_interface": "Интерфейс захвата",
    "hostname": "Имя хоста",
    "default_route": "Маршрут по умолчанию",
    "gateway": "шлюз",
    "via": "через",
    "not_recorded": "не зафиксировано",
    "interface": "Интерфейс",
    "state": "Состояние",
    "addresses": "Адреса",
    "no_interfaces": "Снимок интерфейсов не сохранён.",
    "passive": "Пассивная оценка сегмента",
    "duration": "Длительность, с",
    "visibility": "Видимость",
    "port_hint": "Подсказка типа порта",
    "tagged_frames": "Тегированные кадры",
    "untagged": "Нетегированный трафик",
    "neighbors": "Соседи CDP/LLDP",
    "no_neighbors": "Объявлений CDP/LLDP не зафиксировано.",
    "protocol": "Протокол",
    "neighbor_name": "Имя / device ID",
    "port": "Порт",
    "native_vlan": "native VLAN",
    "voice_vlan": "voice VLAN",
    "stp_bpdus": "BPDU",
    "stp_root": "корневой мост",
    "arp_hosts": "Узлы ARP",
    "servers": "Серверы",
    "routers": "Маршрутизаторы",
    "naming": "Имена mDNS / LLMNR / NBNS",
    "hits": "Срабатывания",
    "scope": "Сеть для сканирования",
    "confirmed": "Подтверждена",
    "profile": "Профиль",
    "address_count": "Число адресов",
    "timing": "Тайминг",
    "targets": "Цели",
    "none": "нет",
    "none_period": "Нет.",
    "audit_scope_snapshot": "Снимок сети аудита",
    "no_assets": "Для этого аудита устройства не сохранены.",
    "vendor": "Производитель",
    "names": "Имена",
    "no_services": "Для этого аудита службы не сохранены.",
    "asset": "Устройство",
    "proto": "Протокол",
    "port": "Порт",
    "service": "Служба",
    "product": "Продукт",
    "no_findings": "Для этого аудита слабых мест не сохранено.",
    "confidence": "уверенность",
    "rationale": "Обоснование",
    "recommendation": "Рекомендация",
    "observations": "наблюдения",
    "evidence": "доказательства",
    "recommendations": "Рекомендации",
    "no_recommendations": "Рекомендаций по открытым слабым местам нет.",
    "finding_count": "шт.",
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
    "confidence.high": "высокая",
    "confidence.medium": "средняя",
    "confidence.low": "низкая",
    "confidence.unknown": "неизвестно",
    "confidence.confirmed": "подтверждено",
    "confidence.hint": "подсказка",
    "status.open": "открыта",
    "status.suppressed": "подавлена",
    "status.accepted_risk": "принятый риск",
    "severity.critical": "критическая",
    "severity.high": "высокая",
    "severity.medium": "средняя",
    "severity.low": "низкая",
    "severity.info": "инфо",
}

_HEADLINES = {
    "Open critical findings require attention": (
        "Есть критические слабые места — разберите в первую очередь"
    ),
    "Open high-severity findings were identified": (
        "Есть слабые места высокой важности"
    ),
    "Open medium-severity findings were identified": (
        "Есть слабые места средней важности"
    ),
    "Open findings were recorded": "Зафиксированы слабые места",
    "No open findings were recorded for the confirmed scope": (
        "По подтверждённой сети открытых слабых мест нет"
    ),
    "No open findings were recorded": "Открытых слабых мест не зафиксировано",
    "Capture completed with no frames": (
        "Захват завершён: кадров нет. Сегмент мог быть тихим."
    ),
    "Untagged traffic was observed; VLAN ID is unknown": (
        "Наблюдался нетегированный трафик; ID VLAN неизвестен"
    ),
    "Passive observations were recorded": (
        "Зафиксированы пассивные наблюдения"
    ),
    "No hosts, services, or findings were recorded": (
        "Хосты, службы и слабые места не зафиксированы"
    ),
}


_SEGMENT_NOTES = {
    "The segment looked quiet: no frames were captured": (
        "Сегмент выглядел тихим: кадров не зафиксировано."
    ),
    "Untagged traffic was observed; VLAN ID is unknown": (
        "Наблюдался нетегированный трафик; ID VLAN неизвестен."
    ),
    "Network traffic was observed": "Наблюдался сетевой трафик.",
    "No passive capture is stored for this audit": (
        "Прослушивание для этого аудита не сохранено."
    ),
}


def _translate_tagged_note(text: str) -> str | None:
    prefix = "Saw tagged VLANs "
    if text.startswith(prefix):
        return f"В кадрах видны тегированные VLAN {text[len(prefix):]}."
    prefix_low = "Very little traffic was observed ("
    if text.startswith(prefix_low) and text.endswith(" frames)"):
        count = text[len(prefix_low):-len(" frames)")]
        return f"Очень мало трафика ({count} кадров)."
    return None


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
.callout {
  background: #eef4f8;
  border-left: 0.3rem solid #1f618d;
  padding: 0.6rem 0.8rem;
}
.hint { color: #4a4a4a; font-size: 0.92rem; }
@media (max-width: 40rem) {
  body { padding: 0.6rem; }
  table { display: block; overflow-x: auto; }
  h1 { font-size: 1.3rem; }
}
""".replace("\n", "")
