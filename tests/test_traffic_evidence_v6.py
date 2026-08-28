from traffic_analysis.analyzer import FIELDS, TrafficAnalyzer


def _row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in FIELDS) + "\n"


def test_evidence_v6_separates_arp_probe_identity_and_directional_flow():
    rows = [
        _row(
            {
                "frame.number": "1",
                "frame.time_epoch": "1000.0",
                "frame.len": "100",
                "frame.protocols": "eth:ip:tcp:tls",
                "eth.src": "00:11:22:33:44:55",
                "eth.dst": "00:aa:bb:cc:dd:ee",
                "ip.src": "10.0.0.2",
                "ip.dst": "203.0.113.10",
                "tcp.srcport": "51500",
                "tcp.dstport": "443",
            }
        ),
        _row(
            {
                "frame.number": "2",
                "frame.time_epoch": "1000.1",
                "frame.len": "120",
                "frame.protocols": "eth:ip:tcp:tls",
                "eth.src": "00:aa:bb:cc:dd:ee",
                "eth.dst": "00:11:22:33:44:55",
                "ip.src": "203.0.113.10",
                "ip.dst": "10.0.0.2",
                "tcp.srcport": "443",
                "tcp.dstport": "51500",
            }
        ),
        _row(
            {
                "frame.number": "3",
                "frame.time_epoch": "1001.0",
                "frame.len": "60",
                "frame.protocols": "eth:arp",
                "eth.src": "00:00:00:00:00:01",
                "eth.dst": "ff:ff:ff:ff:ff:ff",
                "arp.opcode": "1",
                "arp.src.proto_ipv4": "10.0.0.1",
                "arp.src.hw_mac": "00:00:00:00:00:01",
                "arp.dst.proto_ipv4": "10.0.0.99",
                "arp.dst.hw_mac": "00:00:00:00:00:00",
            }
        ),
        _row(
            {
                "frame.number": "4",
                "frame.time_epoch": "1001.1",
                "frame.len": "60",
                "frame.protocols": "eth:arp",
                "eth.src": "00:00:00:00:00:99",
                "eth.dst": "00:00:00:00:00:01",
                "arp.opcode": "2",
                "arp.src.proto_ipv4": "10.0.0.99",
                "arp.src.hw_mac": "00:00:00:00:00:99",
                "arp.dst.proto_ipv4": "10.0.0.1",
                "arp.dst.hw_mac": "00:00:00:00:00:01",
            }
        ),
        _row(
            {
                "frame.number": "5",
                "frame.time_epoch": "1002.0",
                "frame.len": "60",
                "frame.protocols": "eth:arp",
                "eth.src": "00:00:00:00:00:01",
                "eth.dst": "ff:ff:ff:ff:ff:ff",
                "arp.opcode": "1",
                "arp.src.proto_ipv4": "10.0.0.1",
                "arp.src.hw_mac": "00:00:00:00:00:01",
                "arp.dst.proto_ipv4": "10.0.0.200",
                "arp.dst.hw_mac": "00:00:00:00:00:00",
            }
        ),
    ]

    document = TrafficAnalyzer().analyze_tsv(
        rows,
        source={"capture_job_id": "capture-1", "interface": "Vlan4", "filter": None},
    )

    assert document["schema_version"] == 2
    assert document["evidence_model"]["principle"] == "observations_before_inference"

    context = document["capture_context"]
    assert context["logical_vlan_hint"] == "4"
    assert context["logical_vlan_hint_basis"] == "interface_name_hint"
    assert context["observed_vlan_tags"] == []
    assert context["vlan_tag_visibility"] == "not_observed"

    assert document["arp"]["request_count"] == 2
    assert document["arp"]["reply_count"] == 1
    assert {item["ip"] for item in document["arp"]["probed_targets"]} == {
        "10.0.0.99",
        "10.0.0.200",
    }
    assert document["arp"]["confirmed_responders"][0]["ip"] == "10.0.0.99"

    endpoint_states = {
        item["endpoint"]: item for item in document["endpoint_evidence"]
    }
    assert endpoint_states["10.0.0.99"]["state"] == "confirmed_responder"
    assert endpoint_states["10.0.0.99"]["topology_default_visible"] is True
    assert endpoint_states["10.0.0.200"]["state"] == "probed_target"
    assert endpoint_states["10.0.0.200"]["topology_default_visible"] is False

    identity = {
        (item["ip"], item["mac"]): item
        for item in document["identity_observations"]["links"]
    }
    assert ("10.0.0.2", "00:11:22:33:44:55") in identity
    assert ("10.0.0.99", "00:00:00:00:00:99") in identity
    assert identity[("10.0.0.99", "00:00:00:00:00:99")]["confidence"] == "high"

    flows = document["directional_flows"]
    outbound = next(
        item
        for item in flows
        if item["src_endpoint"] == "10.0.0.2"
        and item["dst_endpoint"] == "203.0.113.10"
    )
    inbound = next(
        item
        for item in flows
        if item["src_endpoint"] == "203.0.113.10"
        and item["dst_endpoint"] == "10.0.0.2"
    )
    assert outbound["src_port"] == 51500
    assert outbound["dst_port"] == 443
    assert outbound["role_inference"]["server_side"] == "destination"
    assert inbound["src_port"] == 443
    assert inbound["dst_port"] == 51500
    assert inbound["role_inference"]["server_side"] == "source"


def test_vlan_packet_evidence_is_kept_separate_from_interface_hint():
    rows = [
        _row(
            {
                "frame.number": "1",
                "frame.time_epoch": "1000.0",
                "frame.len": "80",
                "frame.protocols": "eth:vlan:ip:udp:dns",
                "eth.src": "00:11:22:33:44:55",
                "eth.dst": "00:11:22:33:44:66",
                "ip.src": "10.0.4.10",
                "ip.dst": "10.0.4.53",
                "udp.srcport": "53000",
                "udp.dstport": "53",
                "vlan.id": "40",
            }
        )
    ]

    document = TrafficAnalyzer().analyze_tsv(
        rows,
        source={"capture_job_id": "capture-2", "interface": "Vlan4"},
    )

    context = document["capture_context"]
    assert context["logical_vlan_hint"] == "4"
    assert context["observed_vlan_tags"] == [{"vlan_id": "40", "frames": 1}]
    assert context["vlan_tag_visibility"] == "observed"
