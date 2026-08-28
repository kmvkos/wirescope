"""Offline enrichment for canonical global-analysis documents."""

from __future__ import annotations

import ipaddress
from typing import Any

from global_analysis.evidence_gaps import build_evidence_gaps


GATEWAY_CONSISTENCY_RULE = "GA-GATEWAY-CONSISTENCY-001"
DHCP_CONSISTENCY_RULE = "GA-DHCP-CONSISTENCY-001"
DNS_CONSISTENCY_RULE = "GA-DNS-CONSISTENCY-001"


def enrich_global_analysis(
    document: dict[str, Any],
    *,
    environment: dict[str, Any] | None,
    passive: dict[str, Any] | None,
    topology: dict[str, Any],
    traffic_analysis: dict[str, Any],
    evidence_references: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add cross-source infrastructure checks and traceable source references."""
    audit = document.get("audit") or {}
    interface = str(audit.get("interface") or "")
    environment = environment or {}
    passive = passive or {}

    consistency = {
        "gateway": _compare_sources(
            GATEWAY_CONSISTENCY_RULE,
            {
                "environment": _environment_gateways(environment, interface),
                "passive_dhcp": _values((passive.get("dhcp") or {}).get("routers")),
                "topology": _topology_role_addresses(topology, "gateway"),
            },
        ),
        "dhcp": _compare_sources(
            DHCP_CONSISTENCY_RULE,
            {
                "environment_lease": _environment_dhcp_servers(environment, interface),
                "passive": _values((passive.get("dhcp") or {}).get("servers")),
                "traffic": _traffic_dhcp_servers(traffic_analysis),
            },
        ),
        "dns": _compare_sources(
            DNS_CONSISTENCY_RULE,
            {
                "environment": _environment_dns(environment, interface),
                "traffic": _traffic_dns_servers(traffic_analysis),
                "topology": _topology_role_addresses(topology, "dns"),
            },
        ),
    }
    document["infrastructure_consistency"] = consistency

    lineage = _lineage(
        document,
        topology=topology,
        evidence_references=evidence_references,
    )
    document["evidence_references"] = lineage
    _attach_row_refs(document)

    evidence_gaps = [
        gap
        for gap in build_evidence_gaps(
            document,
            consistency=consistency,
            topology=topology,
            traffic_analysis=traffic_analysis,
        )
        if _gap_has_meaningful_starting_evidence(gap, consistency)
    ]
    _attach_gap_refs(document, evidence_gaps)
    document["evidence_gaps"] = evidence_gaps

    divergent = [name for name, row in consistency.items() if row["status"] == "divergent"]
    insufficient_all = [name for name, row in consistency.items() if row["status"] == "insufficient"]
    insufficient_with_evidence = [
        name
        for name, row in consistency.items()
        if row["status"] == "insufficient" and _has_any_source_value(row)
    ]
    document["operator_summary"] = _operator_summary(
        document,
        divergent=divergent,
        insufficient=insufficient_with_evidence,
        evidence_gaps=evidence_gaps,
    )
    summary = document.setdefault("summary", {})
    summary["infrastructure_consistency_divergent"] = len(divergent)
    summary["infrastructure_consistency_insufficient"] = len(insufficient_all)
    summary["evidence_gaps"] = len(evidence_gaps)
    summary["evidence_gaps_high"] = sum(1 for row in evidence_gaps if row.get("priority") == "high")
    summary["evidence_gaps_medium"] = sum(1 for row in evidence_gaps if row.get("priority") == "medium")
    summary["evidence_gaps_low"] = sum(1 for row in evidence_gaps if row.get("priority") == "low")
    summary["evidence_status"] = "needs_evidence" if evidence_gaps else "sufficient"
    return document


def _has_any_source_value(row: dict[str, Any]) -> bool:
    sources = row.get("sources") if isinstance(row.get("sources"), dict) else {}
    return any(bool(values) for values in sources.values())


def _gap_has_meaningful_starting_evidence(
    gap: dict[str, Any],
    consistency: dict[str, Any],
) -> bool:
    category = str(gap.get("category") or "")
    if not category.startswith("infrastructure_") or gap.get("status") != "needs_evidence":
        return True
    domain = category.removeprefix("infrastructure_")
    row = consistency.get(domain)
    return isinstance(row, dict) and _has_any_source_value(row)


def _compare_sources(rule_id: str, sources: dict[str, list[str]]) -> dict[str, Any]:
    normalized = {
        name: sorted(set(value for value in values if value))
        for name, values in sources.items()
    }
    available = {name: set(values) for name, values in normalized.items() if values}
    if len(available) < 2:
        status = "insufficient"
        common: list[str] = []
    else:
        intersection = set.intersection(*available.values())
        common = sorted(intersection)
        status = "consistent" if intersection else "divergent"
    return {
        "rule_id": rule_id,
        "status": status,
        "sources": normalized,
        "common_values": common,
        "confidence": "confirmed" if status == "consistent" else "observed" if status == "divergent" else "unknown",
    }


def _environment_gateways(environment: dict[str, Any], interface: str) -> list[str]:
    values: list[Any] = []
    for route in environment.get("default_routes") or []:
        if isinstance(route, dict) and (not interface or str(route.get("interface") or "") == interface):
            values.append(route.get("gateway"))
    legacy = environment.get("default_route")
    if isinstance(legacy, dict) and (not interface or str(legacy.get("interface") or "") == interface):
        values.append(legacy.get("gateway"))
    for lease in environment.get("dhcp_leases") or []:
        if isinstance(lease, dict) and (not interface or str(lease.get("interface") or "") == interface):
            values.extend(lease.get("routers") or [])
    return _values(values)


def _environment_dhcp_servers(environment: dict[str, Any], interface: str) -> list[str]:
    values = []
    for lease in environment.get("dhcp_leases") or []:
        if not isinstance(lease, dict):
            continue
        if interface and str(lease.get("interface") or "") != interface:
            continue
        values.append(lease.get("server_address"))
    return _values(values)


def _environment_dns(environment: dict[str, Any], interface: str) -> list[str]:
    lease_values: list[Any] = []
    for lease in environment.get("dhcp_leases") or []:
        if not isinstance(lease, dict):
            continue
        if interface and str(lease.get("interface") or "") != interface:
            continue
        lease_values.extend(lease.get("dns") or [])
    if lease_values:
        return _values(lease_values)
    return _values(environment.get("dns") or [])


def _traffic_dhcp_servers(traffic: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    intelligence = traffic.get("protocol_intelligence") or {}
    for row in (intelligence.get("dhcp") or {}).get("servers") or []:
        if isinstance(row, dict):
            values.append(row.get("endpoint"))
    for row in (traffic.get("dhcp") or {}).get("server_hints") or []:
        if isinstance(row, dict):
            values.append(row.get("endpoint"))
    return _values(values)


def _traffic_dns_servers(traffic: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    intelligence = traffic.get("protocol_intelligence") or {}
    for row in (intelligence.get("dns") or {}).get("servers") or []:
        if isinstance(row, dict):
            values.append(row.get("endpoint"))
    return _values(values)


def _topology_role_addresses(topology: dict[str, Any], role: str) -> list[str]:
    values: list[Any] = []
    for node in topology.get("nodes") or []:
        if not isinstance(node, dict) or role not in set(node.get("roles") or []):
            continue
        values.extend(node.get("addresses") or [])
    return _values(values)


def _values(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    result: list[str] = []
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            text = str(ipaddress.ip_address(text.split("/", 1)[0]))
        except ValueError:
            pass
        if text not in result:
            result.append(text)
    return result


def _lineage(
    document: dict[str, Any],
    *,
    topology: dict[str, Any],
    evidence_references: list[dict[str, Any]],
) -> dict[str, Any]:
    by_id = {
        str(row.get("id")): row
        for row in evidence_references
        if isinstance(row, dict) and row.get("id")
    }
    topology_artifact_ids: list[str] = []
    for block_name in ("upstream", "snmp_topology", "ssh_topology"):
        block = topology.get(block_name) or {}
        for artifact_id in block.get("artifact_ids") or []:
            text = str(artifact_id)
            if text not in topology_artifact_ids:
                topology_artifact_ids.append(text)
    for row in topology.get("source_errors") or []:
        if isinstance(row, dict) and row.get("artifact_id"):
            text = str(row["artifact_id"])
            if text not in topology_artifact_ids:
                topology_artifact_ids.append(text)

    inputs = document.get("inputs") or {}
    traffic_ref = str(inputs.get("traffic_result_reference") or "") or None
    return {
        "audit_id": (document.get("audit") or {}).get("id"),
        "traffic_analysis": {
            "job_id": inputs.get("traffic_analysis_job_id"),
            "artifact_id": traffic_ref,
            "artifact": by_id.get(traffic_ref) if traffic_ref else None,
        },
        "inventory": {
            "asset_ids": sorted({str(row.get("asset_id")) for row in document.get("asset_traffic_identity") or [] if row.get("asset_id")}),
            "service_ids": sorted({str(row.get("service_id")) for row in document.get("service_usage") or [] if row.get("service_id")}),
        },
        "findings": {
            "finding_ids": sorted({str(row.get("finding_id")) for row in document.get("finding_traffic_relevance") or [] if row.get("finding_id")}),
        },
        "topology": {
            "schema": topology.get("schema"),
            "schema_version": topology.get("schema_version"),
            "artifact_ids": sorted(topology_artifact_ids),
            "partial": bool(topology.get("partial")),
            "source_errors": list(topology.get("source_errors") or []),
        },
        "audit_artifacts": [by_id[key] for key in sorted(by_id)],
    }


def _attach_row_refs(document: dict[str, Any]) -> None:
    traffic_job = (document.get("inputs") or {}).get("traffic_analysis_job_id")
    traffic_artifact = (document.get("inputs") or {}).get("traffic_result_reference")
    for row in document.get("asset_traffic_identity") or []:
        refs = [{"type": "traffic_job", "id": traffic_job}]
        if traffic_artifact:
            refs.append({"type": "artifact", "id": traffic_artifact})
        if row.get("asset_id"):
            refs.append({"type": "asset", "id": row["asset_id"]})
        row["evidence_refs"] = refs
    for row in document.get("service_usage") or []:
        refs = [
            {"type": "asset", "id": row.get("asset_id")},
            {"type": "service", "id": row.get("service_id")},
            {"type": "traffic_job", "id": traffic_job},
        ]
        row["evidence_refs"] = [ref for ref in refs if ref.get("id")]
    for row in document.get("finding_traffic_relevance") or []:
        refs = [{"type": "finding", "id": row.get("finding_id")}]
        if row.get("asset_id"):
            refs.append({"type": "asset", "id": row["asset_id"]})
        if row.get("service_id"):
            refs.append({"type": "service", "id": row["service_id"]})
        refs.append({"type": "traffic_job", "id": traffic_job})
        row["evidence_refs"] = [ref for ref in refs if ref.get("id")]
    for row in document.get("external_communications") or []:
        row["evidence_refs"] = [
            {"type": "asset", "id": row.get("asset_id")},
            {"type": "traffic_job", "id": traffic_job},
        ]


def _attach_gap_refs(document: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    traffic_job = (document.get("inputs") or {}).get("traffic_analysis_job_id")
    traffic_artifact = (document.get("inputs") or {}).get("traffic_result_reference")
    for gap in gaps:
        affected = gap.get("affected") if isinstance(gap.get("affected"), dict) else {}
        refs: list[dict[str, Any]] = []
        if traffic_job:
            refs.append({"type": "traffic_job", "id": traffic_job})
        if traffic_artifact:
            refs.append({"type": "artifact", "id": traffic_artifact})
        for asset_id in affected.get("asset_ids") or []:
            refs.append({"type": "asset", "id": asset_id})
        for service_id in affected.get("service_ids") or []:
            refs.append({"type": "service", "id": service_id})
        for finding_id in affected.get("finding_ids") or []:
            refs.append({"type": "finding", "id": finding_id})
        seen: set[tuple[str, str]] = set()
        unique: list[dict[str, Any]] = []
        for ref in refs:
            if not ref.get("id"):
                continue
            key = (str(ref.get("type")), str(ref.get("id")))
            if key in seen:
                continue
            seen.add(key)
            unique.append(ref)
        gap["evidence_refs"] = unique


def _operator_summary(
    document: dict[str, Any],
    *,
    divergent: list[str],
    insufficient: list[str],
    evidence_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = document.get("summary") or {}
    matched = int(summary.get("inventory_assets_observed_in_traffic") or 0)
    total = int(summary.get("inventory_assets") or 0)
    services = int(summary.get("services_observed_in_traffic") or 0)
    external = int(summary.get("external_communications") or 0)
    lines = [
        f"С выбранным PCAP сопоставлено {matched} из {total} inventory assets.",
        f"Наблюдались признаки использования {services} inventory services; внешних коммуникаций с exact-correlated assets: {external}.",
    ]
    if divergent:
        lines.append("Есть расхождения infrastructure evidence: " + ", ".join(divergent) + ".")
    if insufficient:
        lines.append("Для части infrastructure checks недостаточно независимых источников: " + ", ".join(insufficient) + ".")
    if evidence_gaps:
        high = [row for row in evidence_gaps if row.get("priority") == "high"]
        lines.append(
            f"Для {len(evidence_gaps)} групп выводов нужны дополнительные данные"
            + (f"; приоритетных пробелов: {len(high)}" if high else "")
            + ". Ниже указано, чего именно не хватает и как это собрать."
        )
    if document.get("partial"):
        lines.append("Корреляция частичная: см. source_health, coverage и warnings; отсутствие связи с выбранным PCAP не считается доказательством отсутствия объекта или проблемы.")
    return {
        "schema": "global-analysis-summary",
        "schema_version": 1,
        "headline": "Корреляция сохранённых результатов WireScope",
        "lines": lines,
    }
