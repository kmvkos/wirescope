"""Describe what the persisted topology evidence is sufficient to claim.

This module deliberately does not discover anything and does not score a network
against an imagined perfect topology. It answers a narrower auditor question:
which classes of statements are supported by the evidence currently retained,
and which useful sources are missing.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


_STATUS_RANK = {"missing": 0, "partial": 1, "sufficient": 2}


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _domain(
    *,
    status: str,
    title: str,
    statement: str,
    evidence: list[str] | None = None,
    missing: list[str] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    if status not in _STATUS_RANK:
        raise ValueError(f"Unsupported topology coverage status: {status}")
    return {
        "status": status,
        "title": title,
        "statement": statement,
        "evidence": _unique(list(evidence or [])),
        "missing": _unique(list(missing or [])),
        "limitations": _unique(list(limitations or [])),
    }


def _all_provenance(topology: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for item in [*(topology.get("nodes") or []), *(topology.get("edges") or [])]:
        values.update(str(value).lower() for value in (item.get("provenance") or []) if value)
    return values


def _has_role(topology: dict[str, Any], *roles: str) -> bool:
    wanted = set(roles)
    return any(wanted.intersection(set(node.get("roles") or [])) for node in topology.get("nodes") or [])


def _relation_counts(topology: dict[str, Any]) -> Counter[str]:
    return Counter(str(edge.get("relation") or "") for edge in topology.get("edges") or [])


def decorate_completeness(topology: dict[str, Any]) -> dict[str, Any]:
    """Attach a conservative evidence-coverage/claimability summary."""

    nodes = list(topology.get("nodes") or [])
    edges = list(topology.get("edges") or [])
    segments = list(topology.get("segments") or [])
    relations = _relation_counts(topology)
    provenance = _all_provenance(topology)

    assets = [node for node in nodes if node.get("kind") == "asset"]
    responsive_assets = [node for node in assets if str(node.get("state") or "") == "responsive"]
    inventory_status = "sufficient" if responsive_assets else ("partial" if assets else "missing")
    inventory = _domain(
        status=inventory_status,
        title="Инвентаризация",
        statement=(
            "Есть подтверждённые активным аудитом узлы и их атрибуты."
            if inventory_status == "sufficient"
            else "Инвентарь присутствует, но нет подтверждённых responsive assets."
            if inventory_status == "partial"
            else "Нет asset inventory, на который можно опереть структурную карту."
        ),
        evidence=["inventory"] if assets else [],
        missing=[] if responsive_assets else ["responsive asset evidence"],
    )

    gateway_edges = relations["segment_gateway"] + relations["default_gateway"]
    routed_edges = relations["routed_interface"] + relations["route_hop"] + relations["upstream_route"]
    if segments and (gateway_edges or routed_edges or _has_role(topology, "gateway", "router")):
        l3_status = "sufficient"
        l3_statement = "Подсеть и хотя бы один L3 gateway/router relationship подтверждены evidence."
    elif segments:
        l3_status = "partial"
        l3_statement = "Подсеть известна, но gateway/router relationship для неё не подтверждён."
    else:
        l3_status = "missing"
        l3_statement = "Нет подтверждённого subnet context для L3-карты."
    l3_evidence: list[str] = []
    if segments:
        l3_evidence.append("confirmed/audit scope")
    if gateway_edges:
        l3_evidence.append("interface/DHCP gateway evidence")
    if routed_edges:
        l3_evidence.append("route/SNMP/SSH interface evidence")
    l3 = _domain(
        status=l3_status,
        title="L3 / маршрутизация",
        statement=l3_statement,
        evidence=l3_evidence,
        missing=[] if l3_status == "sufficient" else ["interface-specific gateway/route evidence"],
        limitations=[
            "Host-wide default route другого интерфейса не считается шлюзом выбранного audit interface."
        ] if l3_status != "sufficient" else [],
    )

    direct_l2 = relations["layer2_neighbor"]
    switch_ports = sum(
        1
        for edge in edges
        if str(edge.get("mapping_type") or "") == "switch_port"
        or "switch-port" in {str(value).lower() for value in (edge.get("provenance") or [])}
    )
    stp = relations["stp_observed"]
    if direct_l2 and switch_ports:
        l2_status = "sufficient"
        l2_statement = "Есть direct L2 adjacency и switch-port evidence для части физических связей."
    elif direct_l2 or switch_ports or stp:
        l2_status = "partial"
        l2_statement = "Есть отдельные L2 observations, но они не описывают всю физическую LAN."
    else:
        l2_status = "missing"
        l2_statement = "Нет LLDP/CDP/FDB/switch-port evidence для физической L2-карты."
    l2 = _domain(
        status=l2_status,
        title="L2 / физические связи",
        statement=l2_statement,
        evidence=[
            *(["LLDP/CDP/Wi-Fi adjacency"] if direct_l2 else []),
            *(["switch-port/FDB mapping"] if switch_ports else []),
            *(["STP observations"] if stp else []),
        ],
        missing=[] if l2_status == "sufficient" else ["LLDP/CDP and/or managed switch FDB/port evidence"],
        limitations=["Отсутствующий L2 hop не дорисовывается по общей подсети."],
    )

    communication_edges = relations["communication"]
    overlay = topology.get("overlay") or {}
    if overlay and communication_edges:
        traffic_status = "sufficient"
        traffic_statement = "Выбранный persisted PCAP подтверждает наблюдавшиеся communication edges."
    elif overlay:
        traffic_status = "partial"
        traffic_statement = "PCAP overlay выбран, но communication edges в нём не получены."
    else:
        traffic_status = "missing"
        traffic_statement = "PCAP overlay не выбран; отсутствие traffic edges не означает отсутствие трафика."
    traffic = _domain(
        status=traffic_status,
        title="Traffic / PCAP",
        statement=traffic_statement,
        evidence=["selected persisted PCAP analysis"] if overlay else [],
        missing=[] if overlay else ["explicitly selected traffic-analysis result"],
        limitations=["PCAP с одного интерфейса показывает только трафик, видимый этой точке захвата."],
    )

    vlan_nodes = [
        node
        for node in nodes
        if node.get("vlan_ids") or node.get("tagged_vlans") or node.get("untagged_vlans") or node.get("pvid")
    ]
    vlan_edges = [
        edge
        for edge in edges
        if edge.get("vlan_id") is not None
        or edge.get("vlan_ids")
        or edge.get("tagged_vlans")
        or edge.get("untagged_vlans")
        or edge.get("pvid") is not None
    ]
    qbridge = any("q-bridge" in value or "qbridge" in value for value in provenance)
    ssh_bridge_vlan = any(value in provenance for value in {"ssh-bridge-vlan", "ssh-bridge-fdb"}) and any(
        str(edge.get("mapping_type") or "") == "switch_port"
        and (
            edge.get("vlan_ids")
            or edge.get("tagged_vlans")
            or edge.get("untagged_vlans")
            or edge.get("pvid") is not None
        )
        for edge in edges
    )
    passive_vlan = any(value in provenance for value in {"802.1q", "vlan", "qinq"})
    if (qbridge or ssh_bridge_vlan) and (vlan_nodes or vlan_edges):
        vlan_status = "sufficient"
        vlan_statement = "Есть managed-device VLAN membership/PVID/FDB evidence для точечной VLAN-корреляции."
    elif vlan_nodes or vlan_edges or passive_vlan:
        vlan_status = "partial"
        vlan_statement = "VLAN наблюдался, но membership конкретных endpoints подтверждён не полностью."
    else:
        vlan_status = "missing"
        vlan_statement = "VLAN evidence отсутствует; WireScope не назначает устройства VLAN по догадке."
    vlan = _domain(
        status=vlan_status,
        title="VLAN",
        statement=vlan_statement,
        evidence=[
            *(["Q-BRIDGE/FDB/PVID"] if qbridge else []),
            *(["SSH bridge VLAN/FDB"] if ssh_bridge_vlan else []),
            *(["802.1Q observation"] if passive_vlan else []),
        ],
        missing=[] if vlan_status == "sufficient" else ["Q-BRIDGE/FDB/PVID or equivalent read-only managed-device evidence"],
    )

    wifi_evidence = any(
        token in value
        for value in provenance
        for token in ("wifi", "wlan", "802.11", "association")
    )
    wifi = _domain(
        status="sufficient" if wifi_evidence else "missing",
        title="Wi‑Fi association",
        statement=(
            "Есть management-plane evidence о Wi‑Fi association."
            if wifi_evidence
            else "Нет данных AP/client association; Wi‑Fi attachment нельзя доказать сетевым inventory alone."
        ),
        evidence=["Wi‑Fi management-plane evidence"] if wifi_evidence else [],
        missing=[] if wifi_evidence else ["AP/router association table via SNMP/SSH/API"],
    )

    hypervisor_evidence = any(
        token in value
        for value in provenance
        for token in ("hypervisor", "vmware", "libvirt", "virtualization-host")
    )
    hypervisor = _domain(
        status="sufficient" if hypervisor_evidence else "missing",
        title="VM / hypervisor placement",
        statement=(
            "Есть out-of-band evidence, связывающее guest с hypervisor host."
            if hypervisor_evidence
            else "По обычной LAN нельзя доказать, на каком физическом hypervisor живёт конкретная VM."
        ),
        evidence=["hypervisor evidence"] if hypervisor_evidence else [],
        missing=[] if hypervisor_evidence else ["optional hypervisor inventory/helper evidence"],
    )

    source_partial = bool(topology.get("partial")) or bool(topology.get("source_errors"))
    structural_status = min([inventory_status, l3_status], key=lambda value: _STATUS_RANK[value])
    if structural_status == "missing" and inventory_status != "missing" and segments:
        structural_status = "partial"

    recommendations: list[str] = []
    if l3_status != "sufficient":
        recommendations.append("Получить gateway evidence для выбранного интерфейса: DHCP lease/router option, interface route, SNMP или read-only management source.")
    if l2_status != "sufficient":
        recommendations.append("Для физической L2-карты использовать LLDP/CDP и при возможности read-only FDB/switch-port data с управляемого устройства.")
    if vlan_status != "sufficient":
        recommendations.append("Для node↔VLAN claims нужны PVID/tagged/untagged/FDB данные; одного факта наличия 802.1Q недостаточно.")
    if not wifi_evidence:
        recommendations.append("Если Wi‑Fi attachment важен, запросить association table у AP/router через management plane.")

    topology["coverage"] = {
        "schema": "topology-evidence-coverage",
        "schema_version": 1,
        "status": "partial" if source_partial or structural_status != "sufficient" else "sufficient",
        "structural_status": structural_status,
        "source_partial": source_partial,
        "claims": {
            "logical_segment_membership": bool(segments),
            "gateway": l3_status == "sufficient",
            "direct_l2_adjacency": bool(direct_l2),
            "physical_switch_port": bool(switch_ports),
            "vlan_membership": vlan_status == "sufficient",
            "observed_traffic": traffic_status == "sufficient",
            "wifi_association": wifi_evidence,
            "hypervisor_placement": hypervisor_evidence,
        },
        "domains": {
            "inventory": inventory,
            "l3": l3,
            "l2": l2,
            "traffic": traffic,
            "vlan": vlan,
            "wifi": wifi,
            "hypervisor": hypervisor,
        },
        "recommendations": _unique(recommendations),
    }
    return topology


__all__ = ["decorate_completeness"]
