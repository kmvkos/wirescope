from engine.assessment import build_assessment, infer_ipv4_groups


def test_infer_ipv4_groups_marks_results_as_hints():
    groups = infer_ipv4_groups(
        [
            {"ipv4": "10.20.30.1"},
            {"ipv4": "10.20.30.15"},
            {"ipv4": "invalid"},
            {"ipv4": "10.20.40.1"},
        ]
    )

    assert groups == [
        {
            "network_hint": "10.20.30.0/24",
            "hosts_observed": 2,
            "confidence": "hint-only",
        },
        {
            "network_hint": "10.20.40.0/24",
            "hosts_observed": 1,
            "confidence": "hint-only",
        },
    ]


def test_build_assessment_separates_observations_from_inference():
    result = {
        "capture": {"frames": 12},
        "devices": {
            "mac_addresses": [
                {"mac": "00:11:22:33:44:55", "frames": 8},
                {"mac": "66:77:88:99:aa:bb", "frames": 4},
            ]
        },
        "sensors": {
            "vlan": {
                "detected": True,
                "data": [{"id": 10, "frames": 5}],
            },
            "arp": {
                "detected": True,
                "data": [{"ipv4": "192.0.2.10", "mac": "00:11:22:33:44:55"}],
            },
            "dhcp": {"detected": True, "data": {"servers": [], "packets": []}},
            "lldp": {
                "detected": True,
                "data": [{"system_name": "switch-1", "port_id": "Gi1/0/1"}],
            },
            "cdp": {"detected": False, "data": []},
            "ipv6_ra": {
                "detected": True,
                "data": {
                    "routers": [{"ipv6": "fe80::1"}],
                    "advertisements": [],
                },
            },
            "ipv6_ns": {"detected": False, "data": []},
            "ipv6_na": {"detected": False, "data": []},
        },
    }

    assessment = build_assessment(result)

    assert assessment["visibility"]["state"] == "active"
    assert assessment["traffic"]["mac_addresses_observed"] == 2
    assert assessment["layer2"]["tagged_vlans"] == [10]
    assert assessment["layer2"]["port_type_hint"]["value"] == "trunk-like"
    assert assessment["layer2"]["port_type_hint"]["confidence"] == "medium"
    assert assessment["ipv4"]["network_hints"][0]["network_hint"] == "192.0.2.0/24"
    assert assessment["ipv6"]["router_count"] == 1
    assert assessment["services"]["dhcp_observed"] is True


def test_build_assessment_reports_silent_capture_without_overclaiming():
    assessment = build_assessment(
        {
            "capture": {"frames": 0},
            "devices": {"mac_addresses": []},
            "sensors": {},
        }
    )

    assert assessment["visibility"]["state"] == "silent"
    assert assessment["layer2"]["port_type_hint"]["value"] == "unknown"
    assert assessment["layer2"]["port_type_hint"]["confidence"] == "none"
