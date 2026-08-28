from topology.presentation import decorate_presentation


def test_same_ip_different_mac_nodes_get_distinct_operator_labels():
    topology = {
        "segments": [],
        "nodes": [
            {
                "id": "asset:inventory",
                "kind": "asset",
                "label": "10.11.11.37",
                "addresses": ["10.11.11.37"],
                "mac": "00:11:22:33:44:55",
                "roles": [],
                "provenance": ["inventory"],
            },
            {
                "id": "pcap-device:conflict",
                "kind": "network-device",
                "label": "10.11.11.37",
                "addresses": ["10.11.11.37"],
                "mac": "66:77:88:99:aa:bb",
                "roles": ["network-device"],
                "provenance": ["pcap-discovery"],
            },
        ],
        "edges": [],
    }

    result = decorate_presentation(topology)
    presentation = result["presentation"]
    labels = presentation["labels"]

    assert labels["asset:inventory"] != labels["pcap-device:conflict"]
    assert labels["asset:inventory"].startswith("10.11.11.37 · …")
    assert labels["pcap-device:conflict"].startswith("10.11.11.37 · …")
    assert "22:33:44:55" in labels["asset:inventory"]
    assert "88:99:aa:bb" in labels["pcap-device:conflict"]

    conflicts = presentation["identity_label_conflicts"]
    assert len(conflicts) == 1
    assert conflicts[0]["label"] == "10.11.11.37"
    assert conflicts[0]["node_ids"] == ["asset:inventory", "pcap-device:conflict"]
    assert conflicts[0]["macs"] == [
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
    ]


def test_duplicate_label_without_multiple_known_macs_is_not_falsely_declared_identity_conflict():
    topology = {
        "segments": [],
        "nodes": [
            {
                "id": "endpoint:a",
                "kind": "endpoint",
                "label": "host.local",
                "names": ["host.local"],
                "addresses": ["10.11.11.37"],
                "roles": [],
            },
            {
                "id": "endpoint:b",
                "kind": "endpoint",
                "label": "host.local",
                "names": ["host.local"],
                "addresses": ["10.11.11.82"],
                "roles": [],
            },
        ],
        "edges": [],
    }

    result = decorate_presentation(topology)

    assert result["presentation"]["labels"]["endpoint:a"] == "host.local"
    assert result["presentation"]["labels"]["endpoint:b"] == "host.local"
    assert result["presentation"]["identity_label_conflicts"] == []
