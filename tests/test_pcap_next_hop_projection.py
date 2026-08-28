from topology import pcap_next_hop


def test_same_source_and_next_hop_mac_is_counted_and_not_projected(monkeypatch):
    document = {
        "next_hop_evidence": {
            "candidate_count": 1,
            "high_confidence_count": 1,
            "ambiguous": [],
            "candidates": [
                {
                    "source_ip": "10.11.11.82",
                    "source_mac": "00:11:22:33:44:55",
                    "next_hop_ip": "10.11.11.1",
                    "next_hop_mac": "00:11:22:33:44:55",
                    "confidence": "high",
                    "flow_count": 5,
                    "remote_destination_count": 5,
                }
            ],
        }
    }
    monkeypatch.setattr(
        pcap_next_hop,
        "_load_document",
        lambda _services, _job_id: document,
    )
    topology = {
        "overlay": {
            "traffic_analysis_job_id": "pcap-job",
            "compatibility": {"status": "compatible"},
        },
        "nodes": [],
        "edges": [],
    }

    result = pcap_next_hop.decorate_pcap_next_hops(
        object(),
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["overlay"]["next_hop"]["topology_edges_added"] == 0
    assert result["overlay"]["next_hop"]["identity_collision_count"] == 1


def test_two_addresses_already_resolving_to_one_asset_do_not_create_self_loop(monkeypatch):
    document = {
        "next_hop_evidence": {
            "candidate_count": 1,
            "high_confidence_count": 0,
            "ambiguous": [],
            "candidates": [
                {
                    "source_ip": "10.11.11.37",
                    "source_mac": None,
                    "next_hop_ip": "10.11.11.82",
                    "next_hop_mac": None,
                    "confidence": "medium",
                    "flow_count": 1,
                    "remote_destination_count": 1,
                }
            ],
        }
    }
    monkeypatch.setattr(
        pcap_next_hop,
        "_load_document",
        lambda _services, _job_id: document,
    )
    topology = {
        "overlay": {
            "traffic_analysis_job_id": "pcap-job",
            "compatibility": {"status": "partial"},
        },
        "nodes": [
            {
                "id": "asset:multi-address",
                "kind": "asset",
                "label": "host",
                "roles": [],
                "addresses": ["10.11.11.37", "10.11.11.82"],
                "provenance": ["inventory"],
            }
        ],
        "edges": [],
    }

    result = pcap_next_hop.decorate_pcap_next_hops(
        object(),
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    node = result["nodes"][0]
    assert node["roles"] == []
    assert node["provenance"] == ["inventory"]
    assert result["edges"] == []
    assert result["overlay"]["next_hop"]["identity_collision_count"] == 1
