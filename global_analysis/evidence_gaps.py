"""Deterministic evidence-gap guidance for correlated assessment.

The gap model is deliberately bounded. It does not infer attacks, intent, or
behavioural anomalies. It explains which cross-source conclusions cannot be
made from the currently persisted evidence and which additional observations
would make those conclusions stronger.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


EVIDENCE_GAP_RULE = "GA-EVIDENCE-GAP-001"

_SOURCE_LABELS = {
    "environment": "снимок окружения WireScope",
    "environment_lease": "DHCP-аренда интерфейса",
    "passive": "пассивное наблюдение",
    "passive_dhcp": "пассивные DHCP-данные",
    "traffic": "анализ выбранного PCAP",
    "topology": "топология",
}

_INFRA_LABELS = {
    "gateway": "Шлюз по умолчанию",
    "dhcp": "DHCP-сервер",
    "dns": "DNS-сервер",
}


def _stable_id(category: str, affected: Any) -> str:
    payload = json.dumps(
        [EVIDENCE_GAP_RULE, category, affected],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"{EVIDENCE_GAP_RULE.lower()}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _values(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if value is not None and str(value).strip()]


def _sample(values: list[str], limit: int = 6) -> list[str]:
    return values[:limit]


def _gap(
    *,
    category: str,
    priority: str,
    title: str,
    known_evidence: list[str],
    missing_evidence: list[str],
    collection_options: list[str],
    safe_conclusion: str,
    affected: dict[str, Any] | None = None,
    status: str = "needs_evidence",
    related_rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    affected = dict(affected or {})
    stable_affected = {
        key: value
        for key, value in affected.items()
        if key in {"count", "domain", "asset_ids", "service_ids", "finding_ids", "endpoints"}
    }
    return {
        "id": _stable_id(category, stable_affected),
        "rule_id": EVIDENCE_GAP_RULE,
        "category": category,
        "status": status,
        "priority": priority,
        "title": title,
        "known_evidence": list(known_evidence),
        "missing_evidence": list(missing_evidence),
        "collection_options": list(collection_options),
        "safe_conclusion": safe_conclusion,
        "affected": affected,
        "related_rule_ids": sorted({str(value) for value in (related_rule_ids or []) if value}),
    }


def build_evidence_gaps(
    document: dict[str, Any],
    *,
    consistency: dict[str, Any],
    topology: dict[str, Any],
    traffic_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return operator-facing, deterministic evidence gaps.

    Every gap must describe four things: what is already known, what is still
    missing, how the missing evidence can be collected, and the strongest safe
    conclusion that can be made before that evidence exists.
    """
    gaps: list[dict[str, Any]] = []

    for domain in ("gateway", "dhcp", "dns"):
        row = consistency.get(domain) or {}
        status = str(row.get("status") or "insufficient")
        if status not in {"insufficient", "divergent"}:
            continue
        sources = row.get("sources") if isinstance(row.get("sources"), dict) else {}
        available = {
            str(name): _values(values)
            for name, values in sources.items()
            if _values(values)
        }
        missing = [str(name) for name, values in sources.items() if not _values(values)]
        label = _INFRA_LABELS[domain]
        known = [
            f"{_SOURCE_LABELS.get(name, name)}: {', '.join(values)}"
            for name, values in available.items()
        ] or ["Ни один источник не дал пригодного значения."]

        if status == "insufficient":
            missing_text = [
                "Для подтверждения нужны как минимум два независимых источника с совпадающим значением."
            ]
            if missing:
                missing_text.append(
                    "Сейчас нет данных из источников: "
                    + ", ".join(_SOURCE_LABELS.get(name, name) for name in missing)
                    + "."
                )
            option_map = {
                "gateway": [
                    "Снять PCAP на нужном VLAN во время DHCP renew/получения адреса или IPv6 RA, чтобы увидеть объявленный шлюз.",
                    "В «Топология → Дополнительно» собрать SNMP/SSH-данные с управляемого шлюза или L3-коммутатора.",
                    "Повторить аудит на фактическом рабочем интерфейсе, чтобы обновить снимок маршрутов и DHCP-аренды.",
                ],
                "dhcp": [
                    "Снять PCAP на клиентском VLAN во время DHCP DORA/renew и дождаться ответа DHCP-сервера.",
                    "Повторить аудит на интерфейсе с действующей DHCP-арендой, чтобы получить адрес сервера из lease metadata.",
                    "Если DHCP виден не на текущей точке захвата, перенести WireScope или SPAN/зеркалирование в нужный VLAN.",
                ],
                "dns": [
                    "Снять PCAP во время реальных DNS-запросов и ответов, чтобы определить фактически используемый resolver.",
                    "Повторить аудит на рабочем интерфейсе и проверить DNS из DHCP-аренды/системного resolver configuration.",
                    "Если DNS-трафик проходит через другой сегмент, захватить трафик на соответствующем VLAN/SPAN-порту.",
                ],
            }
            gaps.append(
                _gap(
                    category=f"infrastructure_{domain}",
                    priority="high" if domain == "gateway" else "medium",
                    title=f"{label}: данных недостаточно для подтверждения",
                    known_evidence=known,
                    missing_evidence=missing_text,
                    collection_options=option_map[domain],
                    safe_conclusion=(
                        f"WireScope видит отдельные признаки для «{label}», но пока не может подтвердить значение независимым источником."
                    ),
                    affected={"count": 1, "domain": domain},
                    related_rule_ids=[str(row.get("rule_id") or "")],
                )
            )
        else:
            gaps.append(
                _gap(
                    category=f"infrastructure_{domain}",
                    priority="high",
                    status="conflicting_evidence",
                    title=f"{label}: источники расходятся",
                    known_evidence=known,
                    missing_evidence=[
                        "Нужен ещё один независимый источник или повторное наблюдение, чтобы понять, какое значение актуально.",
                        "Следует также исключить различие по времени, интерфейсу или VLAN между уже имеющимися источниками.",
                    ],
                    collection_options=[
                        "Повторить пассивный захват на том же интерфейсе и в том же VLAN, где выполнялся аудит.",
                        "Собрать независимые SNMP/SSH-данные с управляемого сетевого оборудования через «Топология → Дополнительно».",
                        "Сверить время получения DHCP/route/DNS данных и повторить аудит после обновления сетевой конфигурации.",
                    ],
                    safe_conclusion=f"Источники для «{label}» противоречат друг другу; выбирать одно значение автоматически нельзя.",
                    affected={"count": 1, "domain": domain},
                    related_rule_ids=[str(row.get("rule_id") or "")],
                )
            )

    identities = [row for row in document.get("asset_traffic_identity") or [] if isinstance(row, dict)]
    conflicts = [row for row in identities if row.get("match_basis") == "identity_conflict"]
    if conflicts:
        endpoints = [str(row.get("endpoint")) for row in conflicts if row.get("endpoint")]
        candidates = sorted(
            {
                str(candidate)
                for row in conflicts
                for candidate in (row.get("candidate_asset_ids") or [])
                if candidate
            }
        )
        gaps.append(
            _gap(
                category="identity_conflict",
                priority="high",
                title="Неоднозначная идентификация устройств",
                known_evidence=[
                    f"Конечные точки PCAP с несколькими кандидатами: {', '.join(_sample(endpoints)) or '—'}.",
                    f"Кандидаты инвентаря: {', '.join(_sample(candidates)) or '—'}.",
                ],
                missing_evidence=[
                    "Не хватает однозначной привязки IP/MAC к одной записи инвентаря на момент захвата.",
                ],
                collection_options=[
                    "Выполнить активное обнаружение только внутри уже подтверждённого scope для нужного сегмента.",
                    "Снять ARP/DHCP-трафик вокруг спорной конечной точки и сопоставить IP, MAC и lease.",
                    "Использовать SNMP/SSH topology enrichment для FDB/ARP/neighbor-данных управляемого оборудования.",
                ],
                safe_conclusion="WireScope не объединяет спорные конечные точки с устройствами автоматически; связанные выводы остаются частичными.",
                affected={
                    "count": len(conflicts),
                    "endpoints": sorted(endpoints),
                    "asset_ids": candidates,
                },
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in conflicts}),
            )
        )

    unmatched = [
        row
        for row in identities
        if row.get("asset_id") is None
        and row.get("match_basis") != "identity_conflict"
        and row.get("classification") in {"internal_segment", "private_unknown", "unknown"}
    ]
    if unmatched:
        endpoints = sorted({str(row.get("endpoint")) for row in unmatched if row.get("endpoint")})
        gaps.append(
            _gap(
                category="unmatched_internal_endpoints",
                priority="medium",
                title="В PCAP есть внутренние/частные узлы без записи в инвентаре",
                known_evidence=[
                    f"Несопоставленных конечных точек: {len(unmatched)}. Примеры: {', '.join(_sample(endpoints)) or '—'}."
                ],
                missing_evidence=[
                    "Не хватает подтверждённой идентичности узла: IP/MAC/ARP/DHCP или управляемого topology evidence.",
                ],
                collection_options=[
                    "Выполнить активное обнаружение в подтверждённом scope соответствующего сегмента.",
                    "Снять ARP/DHCP-трафик на нужном VLAN, чтобы получить IP↔MAC/lease-привязку.",
                    "Для управляемой сети собрать FDB/ARP/neighbor данные через SNMP/SSH topology enrichment.",
                ],
                safe_conclusion="Эти конечные точки присутствовали в выбранном PCAP, но WireScope пока не может связать их с конкретными устройствами аудита.",
                affected={"count": len(unmatched), "endpoints": endpoints},
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in unmatched}),
            )
        )

    service_usage = [row for row in document.get("service_usage") or [] if isinstance(row, dict)]
    pair_level = [row for row in service_usage if row.get("observed_in_selected_traffic")]
    if pair_level:
        service_ids = sorted({str(row.get("service_id")) for row in pair_level if row.get("service_id")})
        examples = [
            f"{row.get('asset_id') or '—'} {str(row.get('protocol') or '').upper()}/{int(row.get('port') or 0)}"
            for row in pair_level[:6]
        ]
        gaps.append(
            _gap(
                category="service_direction",
                priority="medium",
                title="Использование сервисов видно, но направление подтверждено не полностью",
                known_evidence=[
                    f"Для {len(pair_level)} сервисов в выбранном PCAP найден совпадающий порт на уровне пары узлов. Примеры: {', '.join(examples) or '—'}."
                ],
                missing_evidence=[
                    "Текущий traffic-analysis contract агрегирует destination ports для пары узлов и не доказывает, какая сторона принимала соединение на совпавшем порту.",
                    "Для строгого вывода нужен направленный flow/handshake с определённой стороной сервера.",
                ],
                collection_options=[
                    "Снять двусторонний PCAP, включающий начало соединения (SYN/SYN-ACK), в точке, где видны обе стороны.",
                    "Для критичного случая проверить сохранённый raw PCAP вручную через Wireshark/tshark по IP и порту.",
                    "Если трафик асимметричен, перенести точку захвата или использовать SPAN/зеркалирование, где видны оба направления.",
                ],
                safe_conclusion="Можно утверждать, что обмен с совпадающим сервисным портом наблюдался на уровне пары узлов; нельзя утверждать, что направление к конкретному серверному порту доказано.",
                affected={"count": len(pair_level), "service_ids": service_ids},
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in pair_level}),
            )
        )

    unobserved_services = [row for row in service_usage if not row.get("observed_in_selected_traffic")]
    if unobserved_services:
        service_ids = sorted({str(row.get("service_id")) for row in unobserved_services if row.get("service_id")})
        examples = [
            f"{row.get('asset_id') or '—'} {str(row.get('protocol') or '').upper()}/{int(row.get('port') or 0)}"
            for row in unobserved_services[:6]
        ]
        gaps.append(
            _gap(
                category="service_visibility",
                priority="low",
                title="Доступные сервисы, использование которых не подтверждено PCAP",
                known_evidence=[
                    f"Аудит обнаружил {len(unobserved_services)} сервисов без совпадающего трафика в выбранном PCAP. Примеры: {', '.join(examples) or '—'}."
                ],
                missing_evidence=[
                    "Нет наблюдения использования этих сервисов в выбранном интервале и точке захвата.",
                ],
                collection_options=[
                    "Увеличить длительность захвата и повторить PCAP в период нормальной рабочей активности.",
                    "Перенести точку захвата или SPAN в VLAN/сегмент, через который действительно проходит трафик к сервису.",
                    "Во время захвата выполнить легитимное штатное обращение к сервису, если это допустимо для проверки.",
                ],
                safe_conclusion="Сервисы доступны по результатам аудита, но их фактическое использование выбранным PCAP не подтверждено и не опровергнуто.",
                affected={"count": len(unobserved_services), "service_ids": service_ids},
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in unobserved_services}),
            )
        )

    finding_rows = [row for row in document.get("finding_traffic_relevance") or [] if isinstance(row, dict)]
    uncorrelated_findings = [row for row in finding_rows if row.get("traffic_relevance") == "uncorrelated"]
    if uncorrelated_findings:
        finding_ids = sorted({str(row.get("finding_id")) for row in uncorrelated_findings if row.get("finding_id")})
        gaps.append(
            _gap(
                category="finding_corroboration",
                priority="medium",
                title="Проблемы аудита без подтверждения наблюдаемым трафиком",
                known_evidence=[
                    f"Проблем аудита без связи с выбранным PCAP: {len(uncorrelated_findings)}. IDs: {', '.join(_sample(finding_ids)) or '—'}."
                ],
                missing_evidence=[
                    "Нет наблюдаемого трафика, который можно надёжно связать с затронутым устройством или сервисом в выбранном PCAP.",
                ],
                collection_options=[
                    "Повторить захват в период, когда затронутое устройство или сервис реально используется.",
                    "Если устройство не сопоставлено с PCAP, сначала добрать IP/MAC identity через ARP/DHCP, active discovery или topology enrichment.",
                    "Для сервисной проблемы захватить трафик непосредственно в VLAN/сегменте сервиса.",
                ],
                safe_conclusion="Проблема остаётся выводом активного аудита; выбранный PCAP пока не даёт дополнительного подтверждения её эксплуатационной релевантности.",
                affected={"count": len(uncorrelated_findings), "finding_ids": finding_ids},
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in uncorrelated_findings}),
            )
        )

    coverage = document.get("coverage") or {}
    inventory_missing = [
        row for row in coverage.get("inventory_assets_not_observed") or [] if isinstance(row, dict)
    ]
    if inventory_missing:
        asset_ids = sorted({str(row.get("asset_id")) for row in inventory_missing if row.get("asset_id")})
        gaps.append(
            _gap(
                category="capture_visibility",
                priority="low",
                title="Часть устройств аудита не видна в выбранном PCAP",
                known_evidence=[
                    f"Устройств из инвентаря без наблюдаемой конечной точки в PCAP: {len(inventory_missing)}. IDs: {', '.join(_sample(asset_ids)) or '—'}."
                ],
                missing_evidence=[
                    "Не хватает трафика этих устройств в выбранной точке и интервале захвата.",
                ],
                collection_options=[
                    "Сделать более длительный захват в период обычной активности устройств.",
                    "Перенести WireScope/SPAN в сегмент, где трафик этих устройств действительно проходит.",
                    "При необходимости снять отдельные PCAP для разных VLAN вместо попытки покрыть сеть одной точкой захвата.",
                ],
                safe_conclusion="Отсутствие устройства в выбранном PCAP означает только отсутствие наблюдения в этой точке/интервале, а не отсутствие устройства в сети.",
                affected={"count": len(inventory_missing), "asset_ids": asset_ids},
                related_rule_ids=sorted({str(row.get("rule_id") or "") for row in inventory_missing}),
            )
        )

    if bool(topology.get("partial")):
        topology_coverage = topology.get("coverage") if isinstance(topology.get("coverage"), dict) else {}
        incomplete = [
            f"{name}: {row.get('status')}"
            for name, row in topology_coverage.items()
            if isinstance(row, dict) and str(row.get("status") or "") not in {"sufficient", "complete", "confirmed"}
        ]
        gaps.append(
            _gap(
                category="topology_coverage",
                priority="medium",
                title="Топология неполная — часть связей нельзя подтвердить",
                known_evidence=[
                    "Неполные области покрытия: " + (", ".join(incomplete) if incomplete else "топология помечена как partial") + "."
                ],
                missing_evidence=[
                    "Не хватает структурных L2/L3 или management-данных для части узлов/связей.",
                ],
                collection_options=[
                    "Собрать LLDP/CDP/STP/ARP evidence пассивным наблюдением в нужном сегменте.",
                    "В «Топология → Дополнительно» выполнить SNMP enrichment для FDB/VLAN/LLDP/интерфейсных данных управляемого оборудования.",
                    "При наличии доверенного SSH-доступа выполнить SSH enrichment для route/neighbor/bridge данных.",
                ],
                safe_conclusion="Структурные выводы ограничены подтверждённой частью графа; отсутствующие связи не дорисовываются предположениями.",
                affected={"count": len(incomplete) or 1},
            )
        )

    graph = traffic_analysis.get("communications_graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("edges"), list):
        gaps.append(
            _gap(
                category="traffic_graph",
                priority="high",
                title="Нет пригодного графа коммуникаций PCAP",
                known_evidence=["Выбранный Traffic Analysis не содержит пригодного communications graph."],
                missing_evidence=["Без графа коммуникаций нельзя сопоставлять устройства, сервисы и findings с наблюдаемыми парами узлов."],
                collection_options=[
                    "Повторно выполнить Traffic Analysis для исходного raw PCAP, если файл ещё сохранён.",
                    "Если raw PCAP уже недоступен, снять новый захват и дождаться завершения Traffic Analysis.",
                ],
                safe_conclusion="Корреляция может использовать остальные сохранённые источники, но трафиковые связи остаются неподтверждёнными.",
                affected={"count": 1},
            )
        )

    priority_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        gaps,
        key=lambda row: (
            priority_order.get(str(row.get("priority")), 9),
            str(row.get("category") or ""),
            str(row.get("id") or ""),
        ),
    )


__all__ = ["EVIDENCE_GAP_RULE", "build_evidence_gaps"]
