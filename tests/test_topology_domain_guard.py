from types import SimpleNamespace

from topology import pcap_next_hop, traffic_overlay


def test_different_domain_skips_pcap_next_hop_structural_projection(monkeypatch):
    document = {
        "next_hop_evidence": {
            "candidate_count": 1,
            "high_confidence_count": 1,
            "candidates": [
                {
                    "source_ip": "10.0.18.229",
                    "next_hop_ip": "10.0.0.1",
                    "next_hop_mac": "a8:f9:4b:2e:02:80",
                    "confidence": "high",
                    "flow_count": 10,
                    "remote_destination_count": 7,
                }
            ],
            "ambiguous": [],
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
            "compatibility": {"status": "different_domain"},
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
    assert result["overlay"]["next_hop"]["candidate_count"] == 1
    assert result["overlay"]["next_hop"]["topology_edges_added"] == 0
    assert result["overlay"]["next_hop"]["topology_projection_skipped"] is True
    assert (
        result["overlay"]["next_hop"]["topology_projection_skip_reason"]
        == "different_observation_domain"
    )


def test_different_domain_keeps_discovery_as_overlay_evidence_without_enriching_current_assets(monkeypatch):
    document = {
        "identity_resolution": {
            "candidates": [
                {
                    "candidate_id": "foreign-1",
                    "status": "resolved",
                    "confidence": "high",
                    "mac": "00:11:22:33:44:55",
                    "addresses": ["10.0.0.1"],
                }
            ]
        },
        "endpoint_evidence": [
            {"endpoint": "10.0.0.1", "state": "confirmed_responder"}
        ],
        "discovery_evidence_status": {"status": "available"},
        "discovery_evidence": {
            "devices": [
                {
                    "protocol": "lldp",
                    "source_mac": "00:11:22:33:44:55",
                    "addresses": ["10.0.0.1"],
                    "names": ["foreign-switch"],
                    "roles": ["network-neighbor"],
                }
            ],
            "cdp": {"devices": []},
            "lldp": {"devices": [{"name": "foreign-switch"}]},
            "mndp": {"devices": []},
        },
    }
    monkeypatch.setattr(
        traffic_overlay,
        "_load_document",
        lambda _services, _job_id: document,
    )
    monkeypatch.setattr(
        traffic_overlay,
        "_inventory_assets",
        lambda _services, _audit_id: [],
    )
    monkeypatch.setattr(
        traffic_overlay,
        "assess_observation_domain",
        lambda **_kwargs: {
            "status": "different_domain",
            "matches": {"exact_ips": [], "exact_macs": []},
            "reasons": ["different test domains"],
        },
    )

    services = SimpleNamespace(
        inventory=SimpleNamespace(latest_scope=lambda _audit_id: None),
        jobs=SimpleNamespace(
            get_audit=lambda _audit_id: SimpleNamespace(
                scope={"targets": ["10.11.11.0/24"]},
                interface="ens37",
            )
        ),
    )
    topology = {
        "overlay": {"traffic_analysis_job_id": "pcap-job", "interface": "ens38"},
        "nodes": [
            {
                "id": "asset:current-private-ip",
                "kind": "asset",
                "label": "10.0.0.1",
                "addresses": ["10.0.0.1"],
                "mac": "66:77:88:99:aa:bb",
                "roles": [],
                "provenance": ["inventory"],
            }
        ],
        "edges": [],
        "warnings": [],
    }

    result = traffic_overlay.decorate_traffic_overlay(
        services,
        "audit-1",
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    assert len(result["nodes"]) == 1
    current = result["nodes"][0]
    assert current["id"] == "asset:current-private-ip"
    assert "pcap_state" not in current
    assert "pcap_local_identity" not in current
    assert "pcap-identity" not in current["provenance"]

    assert result["overlay"]["topology_enrichment"]["allowed"] is False
    assert (
        result["overlay"]["topology_enrichment"]["status"]
        == "skipped_different_domain"
    )
    assert result["overlay"]["topology_enrichment"]["endpoint_annotation_applied"] is False
    assert result["overlay"]["discovery"]["device_count"] == 1
    assert result["overlay"]["discovery"]["lldp_devices"] == 1
    assert result["overlay"]["discovery"]["topology_nodes_added"] == 0
    assert result["overlay"]["discovery"]["topology_enrichment_skipped"] is True
    assert (
        result["overlay"]["discovery"]["topology_enrichment_skip_reason"]
        == "different_observation_domain"
    )
    assert any("другому observation domain" in item for item in result["warnings"])


def test_same_ip_different_mac_does_not_overwrite_inventory_identity_during_pcap_enrichment():
    topology = {
        "nodes": [
            {
                "id": "asset:inventory-host",
                "kind": "asset",
                "label": "10.11.11.37",
                "addresses": ["10.11.11.37"],
                "mac": "00:11:22:33:44:55",
                "roles": [],
                "provenance": ["inventory"],
            }
        ],
        "edges": [],
    }
    document = {
        "identity_resolution": {
            "candidates": [
                {
                    "candidate_id": "pcap-conflict",
                    "status": "resolved",
                    "confidence": "high",
                    "mac": "66:77:88:99:aa:bb",
                    "addresses": ["10.11.11.37"],
                }
            ]
        },
        "endpoint_evidence": [
            {"endpoint": "10.11.11.37", "state": "confirmed_responder"}
        ],
        "discovery_evidence": {
            "devices": [
                {
                    "protocol": "lldp",
                    "source_mac": "66:77:88:99:aa:bb",
                    "addresses": ["10.11.11.37"],
                    "names": ["pcap-switch"],
                    "roles": ["network-neighbor"],
                }
            ]
        },
    }

    traffic_overlay._annotate_endpoint_states(topology, document)
    added = traffic_overlay._enrich_discovery_devices(
        topology,
        document,
        "pcap-job",
    )

    assert added == 1
    assert len(topology["nodes"]) == 2

    inventory = next(node for node in topology["nodes"] if node["id"] == "asset:inventory-host")
    assert inventory["mac"] == "00:11:22:33:44:55"
    assert inventory["kind"] == "asset"
    assert inventory["provenance"] == ["inventory"]
    assert "pcap_state" not in inventory
    assert "pcap_local_identity" not in inventory

    pcap_device = next(node for node in topology["nodes"] if node["id"] != "asset:inventory-host")
    assert pcap_device["kind"] == "network-device"
    assert pcap_device["mac"] == "66:77:88:99:aa:bb"
    assert pcap_device["addresses"] == ["10.11.11.37"]
    assert pcap_device["names"] == ["pcap-switch"]
    assert "pcap-discovery" in pcap_device["provenance"]
