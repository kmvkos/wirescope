"""Project extended persisted SNMP evidence into the canonical topology.

This layer is deliberately conservative:
- an SNMP interface address proves that the managed device owns that address
  and observes a connected prefix, but it does not expand active scan scope;
- ARP/ND neighbor-cache rows create topology-only endpoints when inventory has
  no matching asset;
- VLAN membership is assigned to an endpoint only when the FDB itself is
  VLAN-specific or an access-port membership is unambiguous;
- trunk/hybrid ports never force a host into one VLAN.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
from typing import Any

from topology.snmp import (
    _aliases,
    _append_unique,
    _latest_documents,
    _node,
    _norm_ip,
    _norm_mac,
    _safe_id,
)


def decorate_snmp_extended_topology(services, audit_id: str, topology: dict[str, Any]) -> dict[str, Any]:
    documents = _latest_documents(services, audit_id)
    if not documents:
        _merge_stats(topology, Counter())
        return topology
    stats = Counter()
    capabilities: Counter[str] = Counter()
    for artifact_id, document in documents:
        for key, value in (document.get("capabilities") or {}).items():
            if value:
                capabilities[str(key)] += 1
        _decorate_document(topology, document, artifact_id=artifact_id, stats=stats)
    _merge_stats(topology, stats, capabilities=capabilities)
    return topology


def decorate_global_snmp_extended_topology(services, topology: dict[str, Any]) -> dict[str, Any]:
    """Add extended SNMP evidence to the global view without inventing audit scope.

    The global base model intentionally aggregates confirmed scanned segments.
    We therefore enrich managed devices/ports/neighbors and summary metadata,
    but do not promote an SNMP-observed remote connected prefix into the global
    retained-scan segment set.  Per-audit topology shows those observed prefixes.
    """
    audit_ids = [str(item.get("id")) for item in topology.get("audits") or [] if item.get("id")]
    stats = Counter()
    capabilities: Counter[str] = Counter()
    for audit_id in audit_ids:
        for artifact_id, document in _latest_documents(services, audit_id):
            for key, value in (document.get("capabilities") or {}).items():
                if value:
                    capabilities[str(key)] += 1
            _decorate_document(
                topology,
                document,
                artifact_id=artifact_id,
                stats=stats,
                add_observed_segments=False,
            )
    _merge_stats(topology, stats, capabilities=capabilities)
    return topology


def _decorate_document(
    topology: dict[str, Any],
    document: dict[str, Any],
    *,
    artifact_id: str,
    stats: Counter,
    add_observed_segments: bool = True,
) -> None:
    target = _norm_ip(str(document.get("target") or ""))
    if not target:
        return
    nodes = topology.setdefault("nodes", [])
    edges = topology.setdefault("edges", [])
    aliases = _aliases(nodes)
    device_id = aliases["address"].get(target) or f"snmp-device:{target}"
    device = _node(nodes, device_id)
    if device is None:
        # The base SNMP decorator normally creates this node first.  Keep this
        # fallback so the extension remains robust if decoration order changes.
        system = document.get("system") or {}
        device = {
            "id": device_id,
            "kind": "network-device",
            "label": str(system.get("name") or target),
            "roles": ["network-device", "snmp-managed"],
            "addresses": [target],
            "names": [system.get("name")] if system.get("name") else [],
            "confidence": "observed",
            "provenance": ["credentialed-snmp"],
            "snmp_artifact_ids": [artifact_id],
        }
        nodes.append(device)
    _append_unique(device.setdefault("roles", []), "router")
    _append_unique(device.setdefault("provenance", []), "credentialed-snmp-ip-mib")
    _append_unique(device.setdefault("snmp_artifact_ids", []), artifact_id)

    interfaces = {
        int(item["ifindex"]): item
        for item in document.get("interfaces") or []
        if isinstance(item, dict) and isinstance(item.get("ifindex"), int)
    }
    interface_nodes: dict[int, list[str]] = {}
    networks_by_ifindex: dict[int, list[tuple[ipaddress._BaseNetwork, str]]] = {}

    for row in document.get("interface_addresses") or []:
        if not isinstance(row, dict) or not isinstance(row.get("ifindex"), int):
            continue
        ifindex = int(row["ifindex"])
        address = _norm_ip(str(row.get("address") or ""))
        if not address:
            continue
        parsed_address = ipaddress.ip_address(address)
        if parsed_address.is_unspecified or parsed_address.is_multicast:
            continue
        cidr = str(row.get("cidr") or address)
        _append_unique(device.setdefault("addresses", []), cidr)
        stats["interface_addresses"] += 1

        network_text = str(row.get("network") or "")
        network = None
        if network_text:
            try:
                network = ipaddress.ip_network(network_text, strict=False)
            except ValueError:
                network = None
        if network is not None:
            networks_by_ifindex.setdefault(ifindex, []).append((network, _segment_id(target, ifindex, network)))

        interface = interfaces.get(ifindex) or {}
        if_name = str(row.get("interface_name") or interface.get("name") or interface.get("description") or f"ifIndex {ifindex}")
        interface_id = f"snmp-interface:{target}:{ifindex}:{_safe_id(address)}"
        interface_node = _node(nodes, interface_id)
        segment_ids: list[str] = []
        if network is not None and network.prefixlen < network.max_prefixlen and not parsed_address.is_loopback:
            segment_ids = [_segment_id(target, ifindex, network)]
        if interface_node is None:
            interface_node = {
                "id": interface_id,
                "kind": "network-interface",
                "label": f"{if_name} · {cidr}",
                "roles": ["router-interface"],
                "addresses": [cidr],
                "names": [if_name],
                "mac": interface.get("mac"),
                "segment_ids": segment_ids,
                "confidence": "observed",
                "provenance": ["credentialed-snmp-ip-interface"],
                "snmp_artifact_ids": [artifact_id],
                "parent_device_id": device_id,
                "ifindex": ifindex,
                "if_type": interface.get("if_type"),
                "if_type_name": interface.get("if_type_name"),
                "pvid": interface.get("pvid"),
                "vlan_ids": list(interface.get("vlan_ids") or []),
                "tagged_vlans": list(interface.get("tagged_vlans") or []),
                "untagged_vlans": list(interface.get("untagged_vlans") or []),
                "port_mode": interface.get("port_mode") or "unknown",
            }
            nodes.append(interface_node)
            stats["interface_nodes"] += 1
        interface_nodes.setdefault(ifindex, []).append(interface_id)

        edge_id = f"edge:snmp-interface:{target}:{ifindex}:{_safe_id(address)}"
        if not any(edge.get("id") == edge_id for edge in edges):
            edges.append(
                {
                    "id": edge_id,
                    "source": device_id,
                    "target": interface_id,
                    "relation": "routed_interface",
                    "mapping_type": "snmp_ip_interface",
                    "layer": "l3",
                    "confidence": "observed",
                    "provenance": ["credentialed-snmp-ip-interface"],
                    "segment_ids": segment_ids,
                    "ifindex": ifindex,
                    "interface_name": if_name,
                    "address": cidr,
                    "network": network_text or None,
                    "vlan_ids": list(interface.get("vlan_ids") or []),
                    "tagged_vlans": list(interface.get("tagged_vlans") or []),
                    "untagged_vlans": list(interface.get("untagged_vlans") or []),
                    "port_pvid": interface.get("pvid"),
                    "port_mode": interface.get("port_mode") or "unknown",
                    "artifact_id": artifact_id,
                }
            )
            stats["interface_links"] += 1

        if add_observed_segments and segment_ids:
            _upsert_observed_segment(
                topology,
                segment_id=segment_ids[0],
                network=network,
                interface_node_id=interface_id,
                interface_name=if_name,
                source_address=address,
                device_id=device_id,
                target=target,
                ifindex=ifindex,
                artifact_id=artifact_id,
                stats=stats,
            )

    # Enrich already-created switch-port edges with exact tagged/untagged/PVID
    # semantics and derive host VLAN only for an unambiguous access port.
    for edge in edges:
        if edge.get("mapping_type") != "switch_port" or _norm_ip(str(edge.get("switch_management_ip") or "")) != target:
            continue
        ifindex = edge.get("ifindex")
        interface = interfaces.get(int(ifindex)) if isinstance(ifindex, int) else None
        if not interface:
            continue
        tagged = _int_list(interface.get("tagged_vlans"))
        untagged = _int_list(interface.get("untagged_vlans"))
        port_vlans = _int_list(interface.get("vlan_ids"))
        pvid = interface.get("pvid")
        mode = str(interface.get("port_mode") or "unknown")
        edge["tagged_vlans"] = tagged
        edge["untagged_vlans"] = untagged
        edge["port_vlans"] = port_vlans
        edge["port_pvid"] = pvid
        edge["port_mode"] = mode
        effective = _int_list(edge.get("vlan_ids"))
        if not effective and mode == "access" and len(untagged) == 1 and (pvid is None or int(pvid) == untagged[0]):
            effective = list(untagged)
            edge["vlan_ids"] = effective
            _append_unique(edge.setdefault("provenance", []), "snmp-qbridge-access-membership")
        if len(effective) == 1:
            endpoint_id = edge.get("target") if edge.get("source") == device_id else edge.get("source")
            endpoint = _node(nodes, str(endpoint_id))
            if endpoint is not None and endpoint.get("id") != device_id:
                before = set(_int_list(endpoint.get("vlan_ids")))
                _append_unique(endpoint.setdefault("vlan_ids", []), effective[0])
                if effective[0] not in before:
                    stats["vlan_correlations"] += 1
        if mode in {"access", "trunk", "hybrid"}:
            stats[f"ports_{mode}"] += 1

    # Modern IP-MIB neighbor cache (ARP + IPv6 ND).  Invalid/incomplete rows
    # are deliberately not turned into topology nodes.
    aliases = _aliases(nodes)
    for row in document.get("neighbors") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("state") or "").lower() in {"invalid", "incomplete"}:
            continue
        ip = _norm_ip(str(row.get("ip") or ""))
        mac = _norm_mac(str(row.get("mac") or ""))
        if not ip or not mac:
            continue
        ifindex = row.get("ifindex")
        node_id = aliases["address"].get(ip) or aliases["mac"].get(mac)
        if node_id is None:
            node_id = f"snmp-neighbor:{target}:{_safe_id(ip)}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "endpoint",
                    "label": ip,
                    "roles": ["snmp-neighbor"],
                    "addresses": [ip],
                    "names": [],
                    "mac": mac,
                    "confidence": "observed",
                    "provenance": ["snmp-neighbor-cache"],
                    "snmp_artifact_ids": [artifact_id],
                    "segment_ids": [],
                }
            )
            stats["neighbor_nodes"] += 1
        endpoint = _node(nodes, node_id)
        if endpoint is None:
            continue
        if not endpoint.get("mac"):
            endpoint["mac"] = mac
        _append_unique(endpoint.setdefault("provenance", []), "snmp-neighbor-cache")
        _append_unique(endpoint.setdefault("snmp_artifact_ids", []), artifact_id)

        segment_id = _neighbor_segment(ip, int(ifindex) if isinstance(ifindex, int) else None, networks_by_ifindex)
        if segment_id:
            _append_unique(endpoint.setdefault("segment_ids", []), segment_id)
        interface = interfaces.get(int(ifindex)) if isinstance(ifindex, int) else None
        if interface:
            vlan_ids = _int_list(interface.get("vlan_ids"))
            untagged = _int_list(interface.get("untagged_vlans"))
            if str(interface.get("port_mode") or "unknown") == "access" and len(untagged) == 1:
                _append_unique(endpoint.setdefault("vlan_ids", []), untagged[0])
            elif len(vlan_ids) == 1 and int(interface.get("pvid") or vlan_ids[0]) == vlan_ids[0]:
                # A single evidence-backed VLAN on the interface is safe;
                # multi-VLAN interfaces remain unassigned.
                _append_unique(endpoint.setdefault("vlan_ids", []), vlan_ids[0])

        parent_candidates = interface_nodes.get(int(ifindex)) if isinstance(ifindex, int) else None
        if parent_candidates:
            # Prefer the interface address whose network contains the neighbor.
            parent_id = _interface_node_for_neighbor(ip, parent_candidates, nodes)
            edge_id = f"edge:snmp-neighbor:{target}:{ifindex}:{_safe_id(ip)}:{_safe_id(mac)}"
            if not any(edge.get("id") == edge_id for edge in edges):
                edges.append(
                    {
                        "id": edge_id,
                        "source": parent_id,
                        "target": node_id,
                        "relation": "neighbor_cache",
                        "mapping_type": "snmp_neighbor_cache",
                        "layer": "l2",
                        "confidence": "observed",
                        "provenance": [str(row.get("source") or "ipNetToPhysicalTable"), "credentialed-snmp"],
                        "segment_ids": [segment_id] if segment_id else [],
                        "ifindex": ifindex,
                        "interface_name": row.get("interface_name"),
                        "neighbor_state": row.get("state"),
                        "neighbor_type": row.get("type"),
                        "mac": mac,
                        "vlan_ids": _int_list(endpoint.get("vlan_ids")),
                        "artifact_id": artifact_id,
                    }
                )
                stats["neighbor_links"] += 1
        stats["neighbor_correlations"] += 1
        aliases = _aliases(nodes)

    # LLDP management addresses let a chassis/name-only neighbor correlate with
    # a known inventory/router IP without guessing from hostname.
    aliases = _aliases(nodes)
    for neighbor in document.get("lldp_neighbors") or []:
        if not isinstance(neighbor, dict):
            continue
        addresses = [
            normalized
            for value in neighbor.get("remote_management_addresses") or []
            if (normalized := _norm_ip(str(value or "")))
        ]
        if not addresses:
            continue
        chassis = _norm_mac(str(neighbor.get("remote_chassis_id") or ""))
        name = str(neighbor.get("remote_system_name") or "").strip().lower()
        remote_id = aliases["mac"].get(chassis) if chassis else None
        if remote_id is None and name:
            remote_id = aliases["name"].get(name)
        if remote_id is None:
            remote_id = next((aliases["address"].get(address) for address in addresses if aliases["address"].get(address)), None)
        remote = _node(nodes, str(remote_id)) if remote_id else None
        if remote is None:
            continue
        for address in addresses:
            _append_unique(remote.setdefault("addresses", []), address)
        _append_unique(remote.setdefault("provenance", []), "snmp-lldp-management-address")
        stats["lldp_management_correlations"] += 1


def _upsert_observed_segment(
    topology: dict[str, Any],
    *,
    segment_id: str,
    network: ipaddress._BaseNetwork,
    interface_node_id: str,
    interface_name: str,
    source_address: str,
    device_id: str,
    target: str,
    ifindex: int,
    artifact_id: str,
    stats: Counter,
) -> None:
    segments = topology.setdefault("segments", [])
    existing = next((segment for segment in segments if segment.get("id") == segment_id), None)
    if existing is None:
        existing = {
            "id": segment_id,
            "kind": "observed-subnet",
            "label": str(network),
            "network": str(network),
            "family": network.version,
            "prefix_length": network.prefixlen,
            "members": [],
            "gateways": [],
            "interface": interface_name,
            "interfaces": [interface_name],
            "source_address": source_address,
            "directly_connected": True,
            "active_scope": False,
            "confidence": "observed",
            "provenance": ["credentialed-snmp-ip-interface"],
            "snmp_management_target": target,
            "snmp_device_id": device_id,
            "snmp_ifindexes": [ifindex],
            "snmp_artifact_ids": [artifact_id],
        }
        segments.append(existing)
        stats["observed_segments"] += 1
    else:
        _append_unique(existing.setdefault("provenance", []), "credentialed-snmp-ip-interface")
        _append_unique(existing.setdefault("interfaces", []), interface_name)
        _append_unique(existing.setdefault("snmp_ifindexes", []), ifindex)
        _append_unique(existing.setdefault("snmp_artifact_ids", []), artifact_id)
    _append_unique(existing.setdefault("members", []), interface_node_id)


def _segment_id(target: str, ifindex: int, network: ipaddress._BaseNetwork) -> str:
    # IPv6 link-local prefixes are interface scoped and may legitimately occur
    # on many router interfaces, so they cannot use the global network-only ID.
    if network.network_address.is_link_local:
        return f"segment:snmp:{target}:{ifindex}:{network}"
    return f"segment:{network}"


def _neighbor_segment(
    address: str,
    ifindex: int | None,
    networks_by_ifindex: dict[int, list[tuple[ipaddress._BaseNetwork, str]]],
) -> str | None:
    if ifindex is None:
        return None
    parsed = ipaddress.ip_address(address)
    matches = [
        (network.prefixlen, segment_id)
        for network, segment_id in networks_by_ifindex.get(ifindex, [])
        if network.version == parsed.version and parsed in network
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: item[0])[1]


def _interface_node_for_neighbor(address: str, candidates: list[str], nodes: list[dict[str, Any]]) -> str:
    parsed = ipaddress.ip_address(address)
    best: tuple[int, str] | None = None
    for candidate in candidates:
        node = _node(nodes, candidate) or {}
        for raw in node.get("addresses") or []:
            try:
                interface = ipaddress.ip_interface(str(raw))
            except ValueError:
                continue
            if interface.version == parsed.version and parsed in interface.network:
                score = interface.network.prefixlen
                if best is None or score > best[0]:
                    best = (score, candidate)
    return best[1] if best else candidates[0]


def _int_list(values: Any) -> list[int]:
    result: set[int] = set()
    for value in values or []:
        if isinstance(value, int):
            result.add(value)
        elif str(value).isdigit():
            result.add(int(value))
    return sorted(result)


def _merge_stats(topology: dict[str, Any], stats: Counter, *, capabilities: Counter[str] | None = None) -> None:
    snmp = topology.setdefault("snmp_topology", {})
    snmp.update(
        {
            "interface_addresses": stats["interface_addresses"],
            "interface_nodes": stats["interface_nodes"],
            "interface_links": stats["interface_links"],
            "observed_segments": stats["observed_segments"],
            "neighbor_correlations": stats["neighbor_correlations"],
            "neighbor_links": stats["neighbor_links"],
            "lldp_management_correlations": stats["lldp_management_correlations"],
            "ports_access": stats["ports_access"],
            "ports_trunk": stats["ports_trunk"],
            "ports_hybrid": stats["ports_hybrid"],
        }
    )
    if capabilities is not None:
        snmp["capability_devices"] = dict(sorted(capabilities.items()))
    summary = topology.setdefault("summary", {})
    summary["nodes"] = len(topology.get("nodes") or [])
    summary["edges"] = len(topology.get("edges") or [])
    summary["segments"] = len(topology.get("segments") or [])
    summary["snmp_l3_interfaces"] = stats["interface_nodes"]
    summary["snmp_neighbor_links"] = stats["neighbor_links"]
    summary["snmp_observed_segments"] = stats["observed_segments"]
    # Existing base decorator may already have counted VLAN correlations.  Keep
    # the larger value rather than double-counting the same endpoint.
    summary["snmp_vlan_correlations"] = max(
        int(summary.get("snmp_vlan_correlations") or 0),
        stats["vlan_correlations"],
    )
