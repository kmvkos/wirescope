"""Decorate logical topology with persisted credentialed SNMP evidence."""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from sqlalchemy import select

from persistence.models import ArtifactModel


def decorate_snmp_topology(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    documents = _latest_documents(services, audit_id)
    if not documents:
        topology.setdefault("snmp_topology", {"devices": 0, "port_links": 0, "lldp_links": 0})
        return topology
    stats = Counter()
    artifact_ids: list[str] = []
    for artifact_id, document in documents:
        artifact_ids.append(artifact_id)
        _decorate_document(topology, document, artifact_id=artifact_id, stats=stats)
    topology["snmp_topology"] = {
        "devices": stats["devices"],
        "port_links": stats["port_links"],
        "lldp_links": stats["lldp_links"],
        "arp_correlations": stats["arp_correlations"],
        "vlan_correlations": stats["vlan_correlations"],
        "artifact_ids": artifact_ids,
        "confidence": "observed",
        "provenance": ["credentialed-snmp"],
    }
    _refresh_summary(topology, stats)
    return topology


def decorate_global_snmp_topology(services, topology: dict[str, Any]) -> dict[str, Any]:
    audit_ids = [str(item.get("id")) for item in topology.get("audits") or [] if item.get("id")]
    stats = Counter()
    artifacts: list[str] = []
    for audit_id in audit_ids:
        for artifact_id, document in _latest_documents(services, audit_id):
            artifacts.append(artifact_id)
            _decorate_document(topology, document, artifact_id=artifact_id, stats=stats)
    topology["snmp_topology"] = {
        "devices": stats["devices"],
        "port_links": stats["port_links"],
        "lldp_links": stats["lldp_links"],
        "arp_correlations": stats["arp_correlations"],
        "vlan_correlations": stats["vlan_correlations"],
        "artifact_ids": sorted(set(artifacts)),
        "confidence": "observed",
        "provenance": ["credentialed-snmp"],
    }
    _refresh_summary(topology, stats)
    return topology


def _latest_documents(services, audit_id: str) -> list[tuple[str, dict[str, Any]]]:
    with services.database.session() as session:
        rows = session.scalars(
            select(ArtifactModel)
            .where(
                ArtifactModel.audit_id == audit_id,
                ArtifactModel.artifact_type == "snmp_topology_result",
            )
            .order_by(ArtifactModel.created_at.desc())
            .limit(32)
        ).all()
        artifact_ids = [row.id for row in rows]

    result: list[tuple[str, dict[str, Any]]] = []
    seen_targets: set[str] = set()
    for artifact_id in artifact_ids:
        try:
            record = services.jobs.artifact(artifact_id)
            document = services.evidence.read_json(record)
        except Exception:
            continue
        if not isinstance(document, dict) or document.get("schema") != "snmp-topology-result":
            continue
        target = str(document.get("target") or "")
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        result.append((artifact_id, document))
    return result


def _decorate_document(
    topology: dict[str, Any],
    document: dict[str, Any],
    *,
    artifact_id: str,
    stats: Counter,
) -> None:
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    target = str(document.get("target") or "")
    if not target:
        return
    aliases = _aliases(nodes)
    system = document.get("system") or {}
    switch_id = aliases["address"].get(_norm_ip(target))
    if switch_id is None:
        switch_id = f"snmp-device:{target}"
        nodes.append(
            {
                "id": switch_id,
                "kind": "network-device",
                "label": str(system.get("name") or target),
                "roles": ["network-device", "snmp-managed"],
                "addresses": [target],
                "names": [system.get("name")] if system.get("name") else [],
                "confidence": "observed",
                "provenance": ["credentialed-snmp"],
                "snmp_artifact_ids": [artifact_id],
            }
        )
    switch = _node(nodes, switch_id)
    if switch is None:
        return
    _append_unique(switch.setdefault("roles", []), "network-device")
    _append_unique(switch.setdefault("roles", []), "snmp-managed")
    _append_unique(switch.setdefault("provenance", []), "credentialed-snmp")
    _append_unique(switch.setdefault("snmp_artifact_ids", []), artifact_id)
    if system.get("name"):
        _append_unique(switch.setdefault("names", []), str(system["name"]))
        if not switch.get("label") or switch.get("label") == target:
            switch["label"] = str(system["name"])
    if system.get("description"):
        switch["snmp_description"] = str(system["description"])
    switch["snmp_interfaces"] = document.get("interfaces") or []
    switch["snmp_vlans"] = document.get("vlans") or []
    stats["devices"] += 1

    # ARP evidence can resolve an IP-labelled topology node to a MAC before FDB
    # correlation.  Unknown ARP entries stay observed topology endpoints rather
    # than being inserted into the durable inventory.
    aliases = _aliases(nodes)
    for arp in document.get("arp") or []:
        if not isinstance(arp, dict):
            continue
        ip = _norm_ip(str(arp.get("ip") or ""))
        mac = _norm_mac(str(arp.get("mac") or ""))
        if not ip or not mac:
            continue
        node_id = aliases["address"].get(ip) or aliases["mac"].get(mac)
        if node_id is None:
            node_id = f"snmp-arp:{ip}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "endpoint",
                    "label": ip,
                    "roles": ["snmp-arp"],
                    "addresses": [ip],
                    "names": [],
                    "mac": mac,
                    "confidence": "observed",
                    "provenance": ["snmp-arp"],
                    "snmp_artifact_ids": [artifact_id],
                }
            )
        endpoint = _node(nodes, node_id)
        if endpoint is None:
            continue
        if not endpoint.get("mac"):
            endpoint["mac"] = mac
        _append_unique(endpoint.setdefault("provenance", []), "snmp-arp")
        _append_unique(endpoint.setdefault("snmp_artifact_ids", []), artifact_id)
        stats["arp_correlations"] += 1
        aliases = _aliases(nodes)

    aliases = _aliases(nodes)
    interfaces = {
        int(item.get("ifindex")): item
        for item in document.get("interfaces") or []
        if isinstance(item, dict) and isinstance(item.get("ifindex"), int)
    }
    for fdb in document.get("fdb") or []:
        if not isinstance(fdb, dict):
            continue
        mac = _norm_mac(str(fdb.get("mac") or ""))
        if not mac:
            continue
        endpoint_id = aliases["mac"].get(mac)
        if endpoint_id is None or endpoint_id == switch_id:
            continue
        port = int(fdb.get("bridge_port") or 0)
        ifindex = fdb.get("ifindex")
        interface = interfaces.get(int(ifindex)) if isinstance(ifindex, int) else None
        port_name = str(
            fdb.get("interface_name")
            or (interface or {}).get("name")
            or (interface or {}).get("description")
            or (f"bridge-port {port}" if port else "unknown")
        )
        vlan_ids = sorted({int(value) for value in fdb.get("vlan_ids") or [] if isinstance(value, int) or str(value).isdigit()})
        edge_id = f"edge:snmp-fdb:{target}:{mac}:{port}:{','.join(map(str, vlan_ids)) or 'none'}"
        if not any(edge.get("id") == edge_id for edge in edges):
            endpoint = _node(nodes, endpoint_id)
            segment_ids = sorted(set((switch.get("segment_ids") or []) + ((endpoint or {}).get("segment_ids") or [])))
            edges.append(
                {
                    "id": edge_id,
                    "source": switch_id,
                    "target": endpoint_id,
                    "relation": "switch_port",
                    "layer": "l2",
                    "confidence": "observed",
                    "provenance": [str(fdb.get("source") or "snmp-fdb"), "credentialed-snmp"],
                    "segment_ids": segment_ids,
                    "switch_management_ip": target,
                    "bridge_port": port or None,
                    "ifindex": ifindex,
                    "port_name": port_name,
                    "port_pvid": (interface or {}).get("pvid") if interface else None,
                    "port_vlans": (interface or {}).get("vlan_ids") if interface else [],
                    "vlan_ids": vlan_ids,
                    "mac": mac,
                    "artifact_id": artifact_id,
                }
            )
            stats["port_links"] += 1
        if len(vlan_ids) == 1:
            endpoint = _node(nodes, endpoint_id)
            if endpoint is not None:
                _append_unique(endpoint.setdefault("vlan_ids", []), vlan_ids[0])
                _append_unique(endpoint.setdefault("provenance", []), "snmp-qbridge-fdb")
                stats["vlan_correlations"] += 1

    aliases = _aliases(nodes)
    for index, neighbor in enumerate(document.get("lldp_neighbors") or []):
        if not isinstance(neighbor, dict):
            continue
        chassis = _norm_mac(str(neighbor.get("remote_chassis_id") or ""))
        sys_name = str(neighbor.get("remote_system_name") or "").strip()
        remote_id = aliases["mac"].get(chassis) if chassis else None
        if remote_id is None and sys_name:
            remote_id = aliases["name"].get(sys_name.lower())
        if remote_id is None:
            identity = chassis or _safe_id(sys_name) or f"neighbor-{index}"
            remote_id = f"snmp-lldp:{target}:{identity}"
            if not any(node.get("id") == remote_id for node in nodes):
                nodes.append(
                    {
                        "id": remote_id,
                        "kind": "network-device",
                        "label": sys_name or chassis or "LLDP neighbor",
                        "roles": ["network-device", "network-neighbor"],
                        "addresses": [],
                        "names": [sys_name] if sys_name else [],
                        "mac": chassis,
                        "confidence": "observed",
                        "provenance": ["snmp-lldp"],
                        "snmp_artifact_ids": [artifact_id],
                    }
                )
        if remote_id == switch_id:
            continue
        remote = _node(nodes, remote_id)
        if remote is not None:
            _append_unique(remote.setdefault("roles", []), "network-neighbor")
            _append_unique(remote.setdefault("provenance", []), "snmp-lldp")
            _append_unique(remote.setdefault("snmp_artifact_ids", []), artifact_id)
        local_port = str(neighbor.get("local_interface_name") or neighbor.get("local_port_id") or neighbor.get("local_port_num") or "")
        remote_port = str(neighbor.get("remote_port_id") or neighbor.get("remote_port_description") or "")
        edge_id = f"edge:snmp-lldp:{target}:{_safe_id(local_port)}:{remote_id}:{_safe_id(remote_port)}"
        if not any(edge.get("id") == edge_id for edge in edges):
            edges.append(
                {
                    "id": edge_id,
                    "source": switch_id,
                    "target": remote_id,
                    "relation": "snmp_lldp_neighbor",
                    "layer": "l2",
                    "confidence": "observed",
                    "provenance": ["snmp-lldp", "credentialed-snmp"],
                    "segment_ids": sorted(set((switch.get("segment_ids") or []) + ((remote or {}).get("segment_ids") or []))),
                    "local_port": local_port or None,
                    "remote_port": remote_port or None,
                    "remote_chassis_id": neighbor.get("remote_chassis_id"),
                    "remote_system_name": sys_name or None,
                    "artifact_id": artifact_id,
                }
            )
            stats["lldp_links"] += 1

    for warning in document.get("warnings") or []:
        if warning:
            _append_unique(topology.setdefault("warnings", []), str(warning))


def _aliases(nodes: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    result = {"address": {}, "mac": {}, "name": {}}
    for node in nodes:
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        for address in node.get("addresses") or []:
            normalized = _norm_ip(str(address).split("/", 1)[0])
            if normalized:
                result["address"].setdefault(normalized, node_id)
        mac = _norm_mac(str(node.get("mac") or ""))
        if mac:
            result["mac"].setdefault(mac, node_id)
        for name in node.get("names") or []:
            text = str(name or "").strip().lower()
            if text:
                result["name"].setdefault(text, node_id)
        label = str(node.get("label") or "").strip().lower()
        if label:
            result["name"].setdefault(label, node_id)
    return result


def _node(nodes: list[dict[str, Any]], node_id: str) -> dict[str, Any] | None:
    return next((node for node in nodes if node.get("id") == node_id), None)


def _norm_mac(value: str) -> str | None:
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12:
        return None
    return ":".join(compact[index:index + 2].lower() for index in range(0, 12, 2))


def _norm_ip(value: str) -> str | None:
    import ipaddress

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _safe_id(value: str) -> str:
    result = re.sub(r"[^0-9A-Za-z_.:-]+", "-", str(value or "").strip()).strip("-")
    return result[:96]


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _refresh_summary(topology: dict[str, Any], stats: Counter) -> None:
    nodes = topology.get("nodes") or []
    edges = topology.get("edges") or []
    summary = topology.setdefault("summary", {})
    summary["nodes"] = len(nodes)
    summary["edges"] = len(edges)
    summary["snmp_devices"] = stats["devices"]
    summary["switch_port_links"] = stats["port_links"]
    summary["snmp_lldp_links"] = stats["lldp_links"]
    summary["snmp_vlan_correlations"] = stats["vlan_correlations"]
