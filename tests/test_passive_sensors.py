from sensors.passive import arp_sensor, simple_sensor, vlan_sensor


def test_vlan_sensor_aggregates_tagged_frames():
    def fields(_pcap, display_filter, requested_fields):
        assert display_filter == "vlan"
        assert requested_fields == ["vlan.id"]
        return [["10"], ["20"], ["10"], ["10,20"]]

    result = vlan_sensor(fields, lambda *_args: 0, "capture.pcap")

    assert result == {
        "name": "vlan",
        "detected": True,
        "hits": 5,
        "data": [
            {"id": 10, "frames": 3},
            {"id": 20, "frames": 2},
        ],
    }


def test_arp_sensor_normalizes_mac_and_counts_frames():
    def fields(_pcap, _display_filter, _requested_fields):
        return [
            ["192.0.2.10", "AA:BB:CC:DD:EE:FF"],
            ["192.0.2.10", "aa:bb:cc:dd:ee:ff"],
            ["", ""],
        ]

    result = arp_sensor(fields, lambda *_args: 2, "capture.pcap")

    assert result["name"] == "arp"
    assert result["detected"] is True
    assert result["hits"] == 2
    assert result["data"] == [
        {"ipv4": "192.0.2.10", "mac": "aa:bb:cc:dd:ee:ff"}
    ]


def test_simple_sensor_distinguishes_zero_hits():
    result = simple_sensor(
        "ssdp",
        "udp.port == 1900",
        lambda _pcap, display_filter: 0 if display_filter else 1,
        "capture.pcap",
    )

    assert result == {
        "name": "ssdp",
        "detected": False,
        "hits": 0,
        "data": [],
    }
