from topology.traffic_presentation import decorate_traffic_presentation


def test_arp_only_edges_and_hidden_broadcast_counterparts_do_not_leave_mac_wall():
    topology = {
        "overlay": {"traffic_analysis_job_id": "analysis-arp"},
        "nodes": [
            {
                "id": "endpoint:50:ff:20:00:00:01",
                "kind": "endpoint",
                "label": "50:ff:20:00:00:01",
                "addresses": [],
                "provenance": ["pcap"],
            },
            {
                "id": "endpoint:50:ff:20:00:00:02",
                "kind": "endpoint",
                "label": "50:ff:20:00:00:02",
                "addresses": [],
                "provenance": ["pcap"],
            },
            {
                "id": "group:ff:ff:ff:ff:ff:ff",
                "kind": "multicast-group",
                "label": "ff:ff:ff:ff:ff:ff",
                "addresses": [],
                "provenance": ["pcap"],
            },
        ],
        "edges": [
            {
                "id": "edge:1",
                "source": "endpoint:50:ff:20:00:00:01",
                "target": "endpoint:50:ff:20:00:00:02",
                "relation": "communication",
                "protocols": [{"name": "arp", "frames": 1}],
            },
            {
                "id": "edge:2",
                "source": "endpoint:50:ff:20:00:00:01",
                "target": "group:ff:ff:ff:ff:ff:ff",
                "relation": "communication",
                "protocols": [{"name": "arp", "frames": 20}],
            },
        ],
        "presentation": {
            "views": {
                # Broadcast node was already suppressed by the generic presentation layer.
                "traffic": {
                    "node_ids": [
                        "endpoint:50:ff:20:00:00:01",
                        "endpoint:50:ff:20:00:00:02",
                    ],
                    "edge_ids": ["edge:1", "edge:2"],
                },
                "evidence": {
                    "node_ids": [
                        "endpoint:50:ff:20:00:00:01",
                        "endpoint:50:ff:20:00:00:02",
                    ],
                    "edge_ids": ["edge:1", "edge:2"],
                },
            },
            "suppressed": {},
        },
    }

    decorate_traffic_presentation(topology)

    traffic = topology["presentation"]["views"]["traffic"]
    assert traffic["node_ids"] == []
    assert traffic["edge_ids"] == []
    assert traffic["arp_edges_hidden"] == 1
    assert traffic["hidden_endpoint_edges"] == 1

    # Canonical/evidence data is not destroyed.
    assert len(topology["edges"]) == 2
    assert topology["presentation"]["views"]["evidence"]["edge_ids"] == ["edge:1", "edge:2"]
