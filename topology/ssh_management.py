"""Decorate topology with persisted read-only SSH management evidence."""

from __future__ import annotations

from collections import Counter
import ipaddress
import re
from typing import Any

from sqlalchemy import select

from persistence.models import ArtifactModel


def decorate_ssh_management(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    documents = _latest_documents(services, audit_id)
    stats = Counter()
    artifact_ids: list[str] = []
    for artifact_id, document in documents:
        artifact_ids.append(artifact_id)
        _decorate_document(topology, document, artifact_id, stats)
    topology["ssh_topology"] = {
        "devices": stats["devices"],
        "interfaces": stats["interfaces"],
        "neighbors": stats["neighbors"],
        "port_links": stats["port_links"],
        "wifi_links": stats["wifi_links"],
        "connected_segments": stats["connected_segments"],
        "artifact_ids": artifact_ids,
        "provenance": ["credentialed-ssh-readonly"] if artifact_ids else [],
    }
    _refresh_summary(topology)
    return topology


def decorate_global_ssh_management(services, topology: dict[str, Any]) -> dict[str, Any]:
    stats = Counter()
    artifact_ids: list[str] = []
    for audit in topology.get("audits") or []:
        audit_id = str(audit.get("id") or "")
        if not audit_id:
            continue
        for artifact_id, document in _latest_documents(services, audit_id):
            artifact_ids.append(artifact_id)
            _decorate_document(topology, document, artifact_id, stats)
    topology["ssh_topology"] = {
        "devices": stats["devices"],
        "interfaces": stats["interfaces"],
        "neighbors": stats["neighbors"],
        "port_links": stats["port_links"],
        "wifi_links": stats["wifi_links"],
        "connected_segments": stats["connected_segments"],
        "artifact_ids": sorted(set(artifact_ids)),
        "provenance": ["credentialed-ssh-readonly"] if artifact_ids else [],
    }
    _refresh_summary(topology)
    return topology


def _latest_documents(services, audit_id: str) -> list[tuple[str, dict[str, Any]]]:
    with services.database.session() as session:
        rows = session.scalars(
            select(ArtifactModel)
            .where(
                ArtifactModel.audit_id == audit_id,
                ArtifactModel.artifact_type == "ssh_topology_result",
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
        if not isinstance(document, dict) or document.get("schema") != "ssh-topology-result":
            continue
        target = str(document.get("target") or "")
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        result.append((artifact_id, document))
    return result


def _decorate_document(topology: dict[str, Any], document: dict[str, Any], artifact_id: str, stats: Counter) -> None:
    target = _norm_ip(document.get("target"))
    if not target:
        return
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    aliases = _aliases(nodes)
    device_id = aliases["address"].get(target) or f"ssh-device:{target}"
    device = _node(nodes, device_id)
    if device is None:
        device = {
            "id": device_id,
            "kind": "network-device",
            "label": target,
            "roles": ["network-device", "ssh-managed"],
            "addresses": [target],
            "names": [],
            "confidence": "observed",
            "provenance": ["credentialed-ssh-readonly"],
            "ssh_artifact_ids": [artifact_id],
        }
        nodes.append(device)
    _append(device, "roles", "network-device")
    _append(device, "roles", "ssh-managed")
    _append(device, "provenance", "credentialed-ssh-readonly")
    _append(device, "ssh_artifact_ids", artifact_id)
    stats["devices"] += 1

    for interface in document.get("interfaces") or []:
        if not isinstance(interface, dict):
            continue
        name = str(interface.get("name") or "")
        if not name:
            continue
        interface_id = f"ssh-interface:{target}:{_safe(name)}"
        item = _node(nodes, interface_id)
        addresses = [str(value) for value in (interface.get("addresses") or []) if _norm_interface(value)]
        if item is None:
            item = {
                "id": interface_id,
                "kind": "network-interface",
                "label": f"{target} · {name}",
                "roles": ["router-interface"],
                "addresses": addresses,
                "names": [name],
                "mac": _norm_mac(interface.get("mac")),
                "parent_device_id": device_id,
                "confidence": "observed",
                "provenance": ["ssh-ip-addr", "credentialed-ssh-readonly"],
                "ssh_artifact_ids": [artifact_id],
            }
            nodes.append(item)
        stats["interfaces"] += 1
        for raw in addresses:
            parsed = _norm_interface(raw)
            if parsed is None or parsed.ip.is_loopback or parsed.ip.is_link_local or parsed.network.prefixlen >= parsed.network.max_prefixlen:
                continue
            network = str(parsed.network)
            segment_id = f"segment:{network}"
            segment = _ensure_segment(topology, network, interface=name, provenance="ssh-ip-addr")
            _append(item, "segment_ids", segment_id)
            _append(device, "connected_segments", segment_id)
            if device_id not in segment["members"]:
                segment["members"].append(device_id)
            edge_id = f"edge:ssh-interface:{target}:{_safe(name)}:{_safe(network)}"
            if not any(edge.get("id") == edge_id for edge in edges):
                edges.append({
                    "id": edge_id,
                    "source": device_id,
                    "target": interface_id,
                    "relation": "routed_interface",
                    "layer": "l3",
                    "confidence": "observed",
                    "provenance": ["ssh-ip-addr", "credentialed-ssh-readonly"],
                    "segment_id": segment_id,
                    "segment_ids": [segment_id],
                    "interface_name": name,
                    "artifact_id": artifact_id,
                })
                stats["connected_segments"] += 1

    aliases = _aliases(nodes)
    for neighbor in document.get("neighbors") or []:
        if not isinstance(neighbor, dict):
            continue
        address = _norm_ip(neighbor.get("address"))
        mac = _norm_mac(neighbor.get("mac"))
        if not address and not mac:
            continue
        node_id = aliases["address"].get(address or "") or aliases["mac"].get(mac or "")
        if node_id is None:
            identity = address or mac
            node_id = f"ssh-neighbor:{identity}"
            nodes.append({
                "id": node_id,
                "kind": "endpoint",
                "label": address or mac,
                "roles": ["management-neighbor"],
                "addresses": [address] if address else [],
                "names": [],
                "mac": mac,
                "confidence": "observed",
                "provenance": ["ssh-ip-neigh"],
                "ssh_artifact_ids": [artifact_id],
            })
        endpoint = _node(nodes, node_id)
        if endpoint is not None:
            if mac and not endpoint.get("mac"):
                endpoint["mac"] = mac
            _append(endpoint, "provenance", "ssh-ip-neigh")
            _append(endpoint, "ssh_artifact_ids", artifact_id)
            endpoint.setdefault("neighbor_states", {})[target] = neighbor.get("state")
        stats["neighbors"] += 1
        aliases = _aliases(nodes)

    aliases = _aliases(nodes)
    for fdb in document.get("fdb") or []:
        if not isinstance(fdb, dict):
            continue
        mac = _norm_mac(fdb.get("mac"))
        port = str(fdb.get("port") or "")
        if not mac or not port:
            continue
        endpoint_id = aliases["mac"].get(mac)
        if endpoint_id is None or endpoint_id == device_id:
            continue
        vlan_id = fdb.get("vlan_id") if isinstance(fdb.get("vlan_id"), int) else None
        edge_id = f"edge:ssh-fdb:{target}:{mac}:{_safe(port)}:{vlan_id or 'none'}"
        if not any(edge.get("id") == edge_id for edge in edges):
            endpoint = _node(nodes, endpoint_id) or {}
            edges.append({
                "id": edge_id,
                "source": device_id,
                "target": endpoint_id,
                "relation": "layer2_neighbor",
                "mapping_type": "switch_port",
                "layer": "l2",
                "confidence": "observed",
                "provenance": ["ssh-bridge-fdb", "credentialed-ssh-readonly"],
                "segment_ids": sorted(set((device.get("segment_ids") or []) + (endpoint.get("segment_ids") or []))),
                "port_name": port,
                "port_id": port,
                "vlan_ids": [vlan_id] if vlan_id is not None else [],
                "mac": mac,
                "artifact_id": artifact_id,
            })
            stats["port_links"] += 1
        if vlan_id is not None:
            endpoint = _node(nodes, endpoint_id)
            if endpoint is not None:
                _append(endpoint, "vlan_ids", vlan_id)
                _append(endpoint, "provenance", "ssh-bridge-fdb")

    if document.get("vlans"):
        device["ssh_vlan_ports"] = document.get("vlans")
        _append(device, "provenance", "ssh-bridge-vlan")

    aliases = _aliases(nodes)
    for association in document.get("wifi_associations") or []:
        if not isinstance(association, dict):
            continue
        mac = _norm_mac(association.get("mac"))
        if not mac:
            continue
        client_id = aliases["mac"].get(mac)
        if client_id is None:
            client_id = f"ssh-wifi:{mac}"
            nodes.append({
                "id": client_id,
                "kind": "endpoint",
                "label": mac,
                "roles": ["wifi-client"],
                "addresses": [],
                "names": [],
                "mac": mac,
                "confidence": "observed",
                "provenance": ["ssh-wifi-association"],
                "ssh_artifact_ids": [artifact_id],
            })
        client = _node(nodes, client_id)
        if client is not None:
            _append(client, "roles", "wifi-client")
            _append(client, "provenance", "ssh-wifi-association")
            _append(client, "ssh_artifact_ids", artifact_id)
        wifi_interface = str(association.get("interface") or "")
        edge_id = f"edge:ssh-wifi:{target}:{mac}:{_safe(wifi_interface)}"
        if not any(edge.get("id") == edge_id for edge in edges):
            edges.append({
                "id": edge_id,
                "source": device_id,
                "target": client_id,
                "relation": "layer2_neighbor",
                "mapping_type": "wifi_association",
                "layer": "l2",
                "confidence": "observed",
                "provenance": ["ssh-wifi-association", "credentialed-ssh-readonly"],
                "segment_ids": sorted(set((device.get("segment_ids") or []) + ((client or {}).get("segment_ids") or []))),
                "wireless_interface": wifi_interface or None,
                "signal_dbm": association.get("signal_dbm"),
                "rx_bytes": association.get("rx_bytes"),
                "tx_bytes": association.get("tx_bytes"),
                "artifact_id": artifact_id,
            })
            stats["wifi_links"] += 1
        aliases = _aliases(nodes)

    device["ssh_routes"] = document.get("routes") or []
    for route in document.get("routes") or []:
        if not isinstance(route, dict) or str(route.get("destination") or "") != "default":
            continue
        gateway = _norm_ip(route.get("gateway"))
        if not gateway:
            continue
        gateway_id = _aliases(nodes)["address"].get(gateway)
        if gateway_id is None:
            gateway_id = f"ssh-route-gateway:{gateway}"
            nodes.append({
                "id": gateway_id,
                "kind": "endpoint",
                "label": gateway,
                "roles": ["upstream-gateway"],
                "addresses": [gateway],
                "names": [],
                "confidence": "observed",
                "provenance": ["ssh-ip-route"],
                "ssh_artifact_ids": [artifact_id],
            })
        edge_id = f"edge:ssh-default-route:{target}:{gateway}"
        if gateway_id != device_id and not any(edge.get("id") == edge_id for edge in edges):
            edges.append({
                "id": edge_id,
                "source": device_id,
                "target": gateway_id,
                "relation": "upstream_route",
                "layer": "l3",
                "confidence": "observed",
                "provenance": ["ssh-ip-route", "credentialed-ssh-readonly"],
                "segment_ids": [],
                "artifact_id": artifact_id,
            })

    for warning in document.get("warnings") or []:
        if warning:
            _append(topology, "warnings", str(warning))


def _ensure_segment(topology: dict[str, Any], network: str, *, interface: str, provenance: str) -> dict[str, Any]:
    segments = topology.setdefault("segments", [])
    segment_id = f"segment:{network}"
    existing = next((item for item in segments if item.get("id") == segment_id), None)
    if existing is not None:
        return existing
    parsed = ipaddress.ip_network(network, strict=False)
    item = {
        "id": segment_id,
        "kind": "subnet",
        "label": network,
        "network": network,
        "family": parsed.version,
        "prefix_length": parsed.prefixlen,
        "members": [],
        "gateways": [],
        "interface": interface,
        "active_scope": False,
        "confidence": "observed",
        "provenance": [provenance, "credentialed-ssh-readonly"],
    }
    segments.append(item)
    return item


def _aliases(nodes: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    result = {"address": {}, "mac": {}}
    for node in nodes:
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        for raw in node.get("addresses") or []:
            address = _norm_ip(raw)
            if address:
                result["address"].setdefault(address, node_id)
        mac = _norm_mac(node.get("mac"))
        if mac:
            result["mac"].setdefault(mac, node_id)
    return result


def _node(nodes: list[dict[str, Any]], node_id: str) -> dict[str, Any] | None:
    return next((node for node in nodes if str(node.get("id") or "") == node_id), None)


def _append(container: dict[str, Any], field: str, value: Any) -> None:
    values = container.setdefault(field, [])
    if value not in values:
        values.append(value)


def _norm_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").split("/", 1)[0]))
    except ValueError:
        return None


def _norm_interface(value: Any) -> ipaddress._BaseNetwork | ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_interface(str(value or ""))
    except ValueError:
        return None


def _norm_mac(value: Any) -> str | None:
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(compact) != 12:
        return None
    return ":".join(compact[index:index + 2].lower() for index in range(0, 12, 2))


def _safe(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or ""))[:96]


def _refresh_summary(topology: dict[str, Any]) -> None:
    summary = topology.setdefault("summary", {})
    summary["nodes"] = len(topology.get("nodes") or [])
    summary["edges"] = len(topology.get("edges") or [])
    summary["segments"] = len(topology.get("segments") or [])


__all__ = ["decorate_ssh_management", "decorate_global_ssh_management"]
