"""Prevent SNMP management addressing from over-classifying L2 devices as routers."""

from __future__ import annotations

import ipaddress
from typing import Any


def guard_snmp_router_roles(topology: dict[str, Any]) -> dict[str, Any]:
    """Keep ``router`` only when pre-existing or supported by L3 SNMP evidence.

    ``decorate_routed_topology`` runs before SNMP enrichment, so its canonical
    routing metadata records router roles that existed independently of SNMP.
    Extended SNMP may then expose management/interface addresses for both
    routers and ordinary L2 switches. A single management prefix must not turn
    an L2 switch into a router or even a router candidate.
    """
    preexisting = {
        str(item.get("node_id"))
        for item in (topology.get("routing") or {}).get("routers") or []
        if item.get("node_id")
    }

    for node in topology.get("nodes") or []:
        roles = [str(value) for value in (node.get("roles") or []) if value]
        if "snmp-managed" not in roles or "router" not in roles:
            continue
        node_id = str(node.get("id") or "")
        if node_id in preexisting or "gateway" in roles:
            continue

        networks: set[str] = set()
        for child in topology.get("nodes") or []:
            if str(child.get("parent_device_id") or "") != node_id:
                continue
            if "router-interface" not in set(child.get("roles") or []):
                continue
            for raw in child.get("addresses") or []:
                try:
                    interface = ipaddress.ip_interface(str(raw))
                except ValueError:
                    continue
                address = interface.ip
                if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
                    continue
                if interface.network.prefixlen >= interface.network.max_prefixlen:
                    continue
                networks.add(str(interface.network))

        if len(networks) >= 2:
            node["routing_confidence"] = node.get("routing_confidence") or "observed"
            connected = [str(value) for value in (node.get("connected_segments") or []) if value]
            for network in sorted(networks):
                segment_id = f"segment:{network}"
                if segment_id not in connected:
                    connected.append(segment_id)
            node["connected_segments"] = sorted(set(connected))
            continue

        node["roles"] = [
            value for value in roles if value not in {"router", "router-candidate"}
        ]
        node.pop("routing_confidence", None)

    return topology
