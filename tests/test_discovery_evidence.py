from traffic_analysis.discovery import (
    DiscoveryEvidenceAnalyzer,
    merge_discovery_evidence,
)
from traffic_analysis.identity import build_identity_candidates


FIELDS = [
    "frame.time_epoch",
    "frame.protocols",
    "eth.src",
    "ip.src",
    "ipv6.src",
    "cdp.deviceid",
    "cdp.address",
    "cdp.portid",
    "cdp.platform",
    "cdp.software_version",
    "cdp.capabilities",
    "lldp.system.name",
    "lldp.mgn.addr.ip4",
    "lldp.port.id",
    "lldp.system.cap.enabled",
    "pppoed.code",
    "pppoed.tags.service_name",
    "pppoed.tags.ac_name",
    "icmpv6.type",
    "icmpv6.nd.ra.router_lifetime",
    "icmpv6.opt.prefix",
    "icmpv6.opt.prefix_len",
    "icmpv6.opt.src_linkaddr",
    "dhcp.option.dhcp",
    "dhcp.hw.mac_addr",
    "dhcp.option.hostname",
    "dhcp.option.dhcp_server_id",
    "dhcp.ip.your",
    "dhcp.option.router",
    "dhcp.option.domain_name_server",
]


def _row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in FIELDS) + "\n"


def test_discovery_evidence_extracts_topology_signals_without_promoting_pppoe():
    rows = [
        _row(
            {
                "frame.time_epoch": "1000.0",
                "frame.protocols": "eth:llc:cdp",
                "eth.src": "04:f4:1c:0f:18:28",
                "cdp.deviceid": "Muravskaya_38Bk3",
                "cdp.address": "185.246.193.139",
                "cdp.portid": "ether1",
                "cdp.platform": "MikroTik",
                "cdp.software_version": "RouterOS 7.20.2",
                "cdp.capabilities": "0x00000001",
            }
        ),
        _row(
            {
                "frame.time_epoch": "1001.0",
                "frame.protocols": "eth:lldp",
                "eth.src": "00:11:22:33:44:55",
                "lldp.system.name": "access-sw-1",
                "lldp.mgn.addr.ip4": "10.0.0.2",
                "lldp.port.id": "Gi1/0/24",
                "lldp.system.cap.enabled": "0x0004",
            }
        ),
        _row(
            {
                "frame.time_epoch": "1002.0",
                "frame.protocols": "eth:pppoed",
                "eth.src": "00:aa:bb:cc:dd:01",
                "pppoed.code": "0x09",
                "pppoed.tags.service_name": "internet",
            }
        ),
        _row(
            {
                "frame.time_epoch": "1003.0",
                "frame.protocols": "eth:ipv6:icmpv6",
                "eth.src": "00:aa:bb:cc:dd:02",
                "ipv6.src": "fe80::1",
                "icmpv6.type": "134",
                "icmpv6.nd.ra.router_lifetime": "1800",
                "icmpv6.opt.prefix": "2001:db8:1::",
                "icmpv6.opt.prefix_len": "64",
                "icmpv6.opt.src_linkaddr": "00:aa:bb:cc:dd:02",
            }
        ),
        _row(
            {
                "frame.time_epoch": "1004.0",
                "frame.protocols": "eth:ip:udp:dhcp",
                "eth.src": "00:aa:bb:cc:dd:03",
                "ip.src": "10.0.0.1",
                "dhcp.option.dhcp": "5",
                "dhcp.hw.mac_addr": "28:58:74:26:c4:60",
                "dhcp.option.hostname": "host-229",
                "dhcp.option.dhcp_server_id": "10.0.0.1",
                "dhcp.ip.your": "10.0.18.229",
                "dhcp.option.router": "10.0.0.1",
                "dhcp.option.domain_name_server": "185.246.192.22",
            }
        ),
    ]

    document = DiscoveryEvidenceAnalyzer().analyze_tsv(rows, fields=FIELDS)

    assert document["cdp"]["frames"] == 1
    cdp = document["cdp"]["devices"][0]
    assert cdp["names"] == ["Muravskaya_38Bk3"]
    assert cdp["addresses"] == ["185.246.193.139"]
    assert cdp["platform"] == "MikroTik"
    assert cdp["software"] == "RouterOS 7.20.2"
    assert cdp["port_id"] == "ether1"
    assert "router" in cdp["roles"]

    assert document["lldp"]["devices"][0]["addresses"] == ["10.0.0.2"]
    assert "bridge" in document["lldp"]["devices"][0]["roles"]

    assert document["pppoe"]["codes"] == [{"code": "PADI", "frames": 1}]
    assert document["pppoe"]["topology_semantics"] == "discovery_activity_only"
    assert all(
        item["protocol"] != "pppoe"
        for item in document["topology_evidence"]["discovery_devices"]
    )

    ra = document["ipv6_nd"]["router_advertisements"][0]
    assert ra["address"] == "fe80::1"
    assert ra["mac"] == "00:aa:bb:cc:dd:02"
    assert ra["prefixes"] == ["2001:db8:1::/64"]

    assignment = document["dhcp"]["assignments"][0]
    assert assignment["address"] == "10.0.18.229"
    assert assignment["mac"] == "28:58:74:26:c4:60"
    assert assignment["hostname"] == "host-229"
    assert document["network_configuration"]["dhcp_advertised_routers"] == ["10.0.0.1"]
    assert document["network_configuration"]["dhcp_advertised_dns"] == ["185.246.192.22"]

    evidence_types = {
        evidence["type"]
        for link in document["identity_links"]
        for evidence in link["evidence"]
    }
    assert "cdp_advertisement" in evidence_types
    assert "lldp_management" in evidence_types
    assert "router_advertisement" in evidence_types
    assert "dhcp_ack_assignment" in evidence_types


def test_discovery_identity_can_override_generic_external_peer_state():
    document = {
        "identity_observations": {"links": []},
        "endpoint_evidence": [
            {
                "endpoint": "185.246.193.139",
                "state": "external_peer",
                "topology_default_visible": False,
            }
        ],
    }
    discovery = {
        "identity_links": [
            {
                "ip": "185.246.193.139",
                "mac": "04:f4:1c:0f:18:28",
                "confidence": "high",
                "evidence": [{"type": "cdp_advertisement", "count": 1}],
                "first_seen": "2026-08-28T00:00:00+00:00",
                "last_seen": "2026-08-28T00:00:00+00:00",
            }
        ],
        "network_configuration": {},
    }

    merge_discovery_evidence(document, discovery)
    resolved = build_identity_candidates(document)

    assert resolved["resolved_count"] == 1
    candidate = resolved["candidates"][0]
    assert candidate["addresses"] == ["185.246.193.139"]
    assert candidate["mac"] == "04:f4:1c:0f:18:28"
    assert candidate["strong_local_addresses"] == ["185.246.193.139"]
