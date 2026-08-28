from topology.traffic_presentation import decorate_traffic_presentation


def test_external_peers_are_collapsed_only_in_traffic_projection():
    topology = {
        "overlay": {"traffic_analysis_job_id": "analysis-1234567890"},
        "nodes": [
            {
                "id": "asset:1",
                "kind": "asset",
                "label": "host",
                "addresses": ["10.0.0.10"],
                "roles": [],
                "provenance": ["inventory"],
            },
            {
                "id": "endpoint:20.20.20.20",
                "kind": "endpoint",
                "label": "20.20.20.20",
                "addresses": ["20.20.20.20"],
                "roles": [],
                "provenance": ["pcap"],
                "pcap_state": "external_peer",
            },
            {
                "id": "endpoint:30.30.30.30",
                "kind": "endpoint",
                "label": "30.30.30.30",
                "addresses": ["30.30.30.30"],
                "roles": [],
                "provenance": ["pcap"],
                "pcap_state": "external_peer",
            },
        ],
        "edges": [
            {
                "id": "edge:1",
                "source": "asset:1",
                "target": "endpoint:20.20.20.20",
                "relation": "communication",
                "packets": 10,
                "bytes": 1000,
                "protocols": ["tls"],
                "ports": ["tcp/443"],
            },
            {
                "id": "edge:2",
                "source": "asset:1",
                "target": "endpoint:30.30.30.30",
                "relation": "communication",
                "packets": 20,
                "bytes": 2000,
                "protocols": ["quic"],
                "ports": ["udp/443"],
            },
        ],
        "presentation": {
            "views": {
                "traffic": {
                    "node_ids": [
                        "asset:1",
                        "endpoint:20.20.20.20",
                        "endpoint:30.30.30.30",
                    ],
                    "edge_ids": ["edge:1", "edge:2"],
                },
                "evidence": {
                    "node_ids": [
                        "asset:1",
                        "endpoint:20.20.20.20",
                        "endpoint:30.30.30.30",
                    ],
                    "edge_ids": ["edge:1", "edge:2"],
                },
            },
            "suppressed": {},
        },
    }

    decorate_traffic_presentation(topology)

    traffic = topology["presentation"]["views"]["traffic"]
    assert traffic["external_peers_aggregated"] is True
    assert traffic["external_peer_count"] == 2
    assert "endpoint:20.20.20.20" not in traffic["node_ids"]
    assert "endpoint:30.30.30.30" not in traffic["node_ids"]
    group_id = traffic["external_group_node_id"]
    assert group_id in traffic["node_ids"]
    assert len(traffic["edge_ids"]) == 1

    synthetic = next(edge for edge in topology["edges"] if edge["id"] == traffic["edge_ids"][0])
    assert synthetic["aggregated"] is True
    assert synthetic["packets"] == 30
    assert synthetic["bytes"] == 3000
    assert synthetic["external_peer_count"] == 2

    # Raw evidence projection remains untouched and can still be inspected.
    evidence = topology["presentation"]["views"]["evidence"]
    assert evidence["node_ids"] == [
        "asset:1",
        "endpoint:20.20.20.20",
        "endpoint:30.30.30.30",
    ]
    assert evidence["edge_ids"] == ["edge:1", "edge:2"]


def test_strong_local_public_identity_is_not_collapsed_into_internet():
    topology = {
        "overlay": {"traffic_analysis_job_id": "analysis-1"},
        "nodes": [
            {
                "id": "asset:1",
                "kind": "asset",
                "label": "host",
                "addresses": ["10.0.0.10"],
                "provenance": ["inventory"],
            },
            {
                "id": "endpoint:185.246.193.139",
                "kind": "network-device",
                "label": "Muravskaya_38Bk3",
                "addresses": ["185.246.193.139"],
                "provenance": ["pcap", "cdp", "pcap-discovery"],
                "pcap_state": "external_peer",
                "pcap_local_identity": True,
            },
            {
                "id": "endpoint:20.20.20.20",
                "kind": "endpoint",
                "label": "20.20.20.20",
                "addresses": ["20.20.20.20"],
                "provenance": ["pcap"],
                "pcap_state": "external_peer",
            },
        ],
        "edges": [
            {"id": "edge:1", "source": "asset:1", "target": "endpoint:185.246.193.139", "relation": "communication"},
            {"id": "edge:2", "source": "asset:1", "target": "endpoint:20.20.20.20", "relation": "communication"},
        ],
        "presentation": {
            "views": {
                "traffic": {
                    "node_ids": ["asset:1", "endpoint:185.246.193.139", "endpoint:20.20.20.20"],
                    "edge_ids": ["edge:1", "edge:2"],
                }
            },
            "suppressed": {},
        },
    }

    decorate_traffic_presentation(topology)
    traffic = topology["presentation"]["views"]["traffic"]
    assert traffic["external_peers_aggregated"] is False
    assert traffic["external_peer_count"] == 1
    assert "endpoint:185.246.193.139" in traffic["node_ids"]
