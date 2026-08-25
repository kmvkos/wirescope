from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import ipaddress

from jobs.models import RetentionClass
from providers.snmp_topology_extended import (
    IF_PHYS_ADDRESS,
    IF_TYPE,
    IP_ADDRESS_ENTRY,
    IP_ADDRESS_PREFIX_ENTRY,
    IP_ADDR_ENTRY,
    IP_NET_TO_PHYSICAL_ENTRY,
    LLDP_REM_MAN_ADDR_ENTRY,
    normalize_extended_collections,
)
from topology.snmp import decorate_snmp_topology
from topology.snmp_extended import decorate_snmp_extended_topology


def _oid_bytes(address: str) -> str:
    return ".".join(str(value) for value in ipaddress.ip_address(address).packed)


def test_extended_normalization_collects_ipv4_ipv6_neighbors_and_vlan_port_mode():
    ipv6 = "2001:db8:10::1"
    prefix6 = "2001:db8:10::"
    neighbor6 = "2001:db8:10::50"
    collections = {
        "if_type": [
            {"oid": f"{IF_TYPE}.101", "value": 6},
            {"oid": f"{IF_TYPE}.102", "value": 135},
        ],
        "if_phys": [
            {"oid": f"{IF_PHYS_ADDRESS}.101", "value": {"octets": [0, 170, 0, 170, 0, 1]}},
        ],
        "ipv4_addresses": [
            {"oid": f"{IP_ADDR_ENTRY}.1.192.0.2.1", "value": "192.0.2.1"},
            {"oid": f"{IP_ADDR_ENTRY}.2.192.0.2.1", "value": 101},
            {"oid": f"{IP_ADDR_ENTRY}.3.192.0.2.1", "value": "255.255.255.0"},
        ],
        "ip_prefixes": [
            {
                "oid": f"{IP_ADDRESS_PREFIX_ENTRY}.5.102.2.16.{_oid_bytes(prefix6)}.64",
                "value": 1,
            },
        ],
        "ip_addresses": [
            {
                "oid": f"{IP_ADDRESS_ENTRY}.3.2.16.{_oid_bytes(ipv6)}",
                "value": 102,
            },
            {
                "oid": f"{IP_ADDRESS_ENTRY}.4.2.16.{_oid_bytes(ipv6)}",
                "value": 1,
            },
        ],
        "ip_neighbors": [
            {
                "oid": f"{IP_NET_TO_PHYSICAL_ENTRY}.4.102.2.16.{_oid_bytes(neighbor6)}",
                "value": {"octets": [0, 17, 34, 51, 68, 85]},
            },
            {
                "oid": f"{IP_NET_TO_PHYSICAL_ENTRY}.6.102.2.16.{_oid_bytes(neighbor6)}",
                "value": 3,
            },
            {
                "oid": f"{IP_NET_TO_PHYSICAL_ENTRY}.7.102.2.16.{_oid_bytes(neighbor6)}",
                "value": 1,
            },
        ],
        "lldp_management": [
            {
                "oid": f"{LLDP_REM_MAN_ADDR_ENTRY}.3.123.5.1.1.4.192.0.2.2",
                "value": 2,
            },
        ],
    }
    interfaces = [
        {"ifindex": 101, "name": "Gi0/1", "bridge_port": 5, "pvid": 10, "vlan_ids": [10]},
        {"ifindex": 102, "name": "Vlan20", "bridge_port": 6, "pvid": 20, "vlan_ids": [10, 20]},
    ]
    vlans = [
        {"vlan_id": 10, "egress_ports": [5, 6], "untagged_ports": [5]},
        {"vlan_id": 20, "egress_ports": [6], "untagged_ports": [6]},
    ]
    result = normalize_extended_collections(
        collections,
        interfaces=interfaces,
        vlans=vlans,
        legacy_arp=[],
        lldp_neighbors=[{"local_port_num": 5, "remote_system_name": "edge-01"}],
    )

    by_index = {item["ifindex"]: item for item in result["interfaces"]}
    assert by_index[101]["if_type_name"] == "ethernetCsmacd"
    assert by_index[101]["mac"] == "00:aa:00:aa:00:01"
    assert by_index[101]["port_mode"] == "access"
    assert by_index[101]["untagged_vlans"] == [10]
    assert by_index[101]["tagged_vlans"] == []
    assert by_index[102]["port_mode"] == "hybrid"
    assert by_index[102]["tagged_vlans"] == [10]
    assert by_index[102]["untagged_vlans"] == [20]

    addresses = {(item["ifindex"], item["address"]): item for item in result["interface_addresses"]}
    assert addresses[(101, "192.0.2.1")]["network"] == "192.0.2.0/24"
    assert addresses[(102, ipv6)]["network"] == "2001:db8:10::/64"
    assert addresses[(102, ipv6)]["family"] == 6

    assert result["neighbors"] == [
        {
            "ifindex": 102,
            "ip": neighbor6,
            "source": "ipNetToPhysicalTable",
            "mac": "00:11:22:33:44:55",
            "type": "dynamic",
            "type_id": 3,
            "state": "reachable",
            "state_id": 1,
            "interface_name": "Vlan20",
        }
    ]
    assert result["lldp_neighbors"][0]["remote_management_addresses"] == ["192.0.2.2"]


def test_extended_projection_adds_router_interfaces_observed_segments_neighbors_and_access_vlan(
    durable_settings,
    job_service,
    evidence_store,
    database,
):
    audit = job_service.create_audit(profile="deep", interface="eth0", scope={}, actor="auditor")
    document = {
        "schema": "snmp-topology-result",
        "schema_version": 1,
        "status": "completed",
        "target": "192.0.2.1",
        "interface": "eth0",
        "system": {"name": "router-01", "description": "Test router"},
        "interfaces": [
            {
                "ifindex": 101,
                "name": "lan0",
                "bridge_port": 5,
                "pvid": 10,
                "vlan_ids": [10],
                "tagged_vlans": [],
                "untagged_vlans": [10],
                "port_mode": "access",
                "mac": "00:aa:00:aa:00:01",
            },
            {
                "ifindex": 102,
                "name": "lan20",
                "vlan_ids": [],
                "tagged_vlans": [],
                "untagged_vlans": [],
                "port_mode": "unknown",
                "mac": "00:aa:00:aa:00:02",
            },
        ],
        "interface_addresses": [
            {
                "ifindex": 101,
                "interface_name": "lan0",
                "address": "192.0.2.1",
                "prefix_length": 24,
                "cidr": "192.0.2.1/24",
                "network": "192.0.2.0/24",
                "family": 4,
            },
            {
                "ifindex": 102,
                "interface_name": "lan20",
                "address": "10.20.0.1",
                "prefix_length": 24,
                "cidr": "10.20.0.1/24",
                "network": "10.20.0.0/24",
                "family": 4,
            },
        ],
        "fdb": [
            {
                "mac": "00:11:22:33:44:55",
                "bridge_port": 5,
                "ifindex": 101,
                "interface_name": "lan0",
                "vlan_ids": [],
                "source": "bridge-fdb",
            }
        ],
        "arp": [],
        "neighbors": [
            {
                "ip": "10.20.0.50",
                "mac": "00:22:33:44:55:66",
                "ifindex": 102,
                "interface_name": "lan20",
                "type": "dynamic",
                "state": "reachable",
                "source": "ipNetToPhysicalTable",
            }
        ],
        "lldp_neighbors": [],
        "vlans": [{"vlan_id": 10, "name": "users", "egress_ports": [5], "untagged_ports": [5]}],
        "capabilities": {
            "interfaces": True,
            "interface_addresses": True,
            "neighbor_cache": True,
            "bridge_fdb": True,
            "vlans": True,
            "lldp": False,
        },
        "warnings": [],
    }
    evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="snmp_topology_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="snmp-topology-result",
        schema_version=1,
    )
    topology = {
        "schema": "network-topology",
        "nodes": [
            {
                "id": "asset:router",
                "kind": "asset",
                "label": "192.0.2.1",
                "roles": ["network-device"],
                "addresses": ["192.0.2.1"],
                "names": [],
                "mac": "00:aa:00:aa:00:01",
                "segment_ids": ["segment:192.0.2.0/24"],
                "confidence": "observed",
                "provenance": ["nmap"],
            },
            {
                "id": "asset:server",
                "kind": "asset",
                "label": "server01",
                "roles": [],
                "addresses": ["192.0.2.10"],
                "names": ["server01"],
                "mac": "00:11:22:33:44:55",
                "segment_ids": ["segment:192.0.2.0/24"],
                "confidence": "observed",
                "provenance": ["nmap"],
            },
        ],
        "edges": [],
        "segments": [
            {
                "id": "segment:192.0.2.0/24",
                "network": "192.0.2.0/24",
                "members": ["asset:router", "asset:server"],
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            }
        ],
        "warnings": [],
        "summary": {},
    }
    services = SimpleNamespace(database=database, jobs=job_service, evidence=evidence_store)
    result = decorate_snmp_topology(services, audit.id, topology)
    result = decorate_snmp_extended_topology(services, audit.id, result)

    router = next(node for node in result["nodes"] if node["id"] == "asset:router")
    assert "10.20.0.1/24" in router["addresses"]
    assert "router" in router["roles"]

    observed = next(segment for segment in result["segments"] if segment.get("network") == "10.20.0.0/24")
    assert observed["active_scope"] is False
    assert observed["confidence"] == "observed"
    assert "credentialed-snmp-ip-interface" in observed["provenance"]

    interfaces = [node for node in result["nodes"] if node.get("kind") == "network-interface"]
    assert len(interfaces) == 2
    assert any(node.get("label") == "lan20 · 10.20.0.1/24" for node in interfaces)
    assert any(edge.get("relation") == "routed_interface" and edge.get("network") == "10.20.0.0/24" for edge in result["edges"])

    neighbor = next(node for node in result["nodes"] if "10.20.0.50" in (node.get("addresses") or []))
    assert neighbor["mac"] == "00:22:33:44:55:66"
    assert "segment:10.20.0.0/24" in neighbor["segment_ids"]
    assert any(edge.get("mapping_type") == "snmp_neighbor_cache" and edge.get("target") == neighbor["id"] for edge in result["edges"])

    port_edge = next(edge for edge in result["edges"] if edge.get("mapping_type") == "switch_port")
    assert port_edge["port_mode"] == "access"
    assert port_edge["untagged_vlans"] == [10]
    assert port_edge["vlan_ids"] == [10]
    server = next(node for node in result["nodes"] if node["id"] == "asset:server")
    assert server["vlan_ids"] == [10]
    assert result["snmp_topology"]["observed_segments"] == 1
    assert result["snmp_topology"]["neighbor_links"] == 1
