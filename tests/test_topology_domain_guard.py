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


def test_different_domain_keeps_discovery_as_overlay_evidence_without_adding_devices(monkeypatch):
    document = {
        "identity_resolution": {"candidates": []},
        "endpoint_evidence": [],
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
        "nodes": [],
        "edges": [],
        "warnings": [],
    }

    result = traffic_overlay.decorate_traffic_overlay(
        services,
        "audit-1",
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    assert result["nodes"] == []
    assert result["overlay"]["discovery"]["device_count"] == 1
    assert result["overlay"]["discovery"]["lldp_devices"] == 1
    assert result["overlay"]["discovery"]["topology_nodes_added"] == 0
    assert result["overlay"]["discovery"]["topology_enrichment_skipped"] is True
    assert (
        result["overlay"]["discovery"]["topology_enrichment_skip_reason"]
        == "different_observation_domain"
    )
    assert any("другому observation domain" in item for item in result["warnings"])
