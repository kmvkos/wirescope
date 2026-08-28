from types import SimpleNamespace

import pytest

from topology import traffic_overlay


def _document() -> dict:
    return {
        "identity_resolution": {
            "candidate_count": 1,
            "resolved_count": 1,
            "candidates": [
                {
                    "candidate_id": "pcap-device",
                    "status": "resolved",
                    "confidence": "high",
                    "mac": "00:11:22:33:44:55",
                    "addresses": ["10.11.11.37"],
                }
            ],
        },
        "endpoint_evidence": [
            {"endpoint": "10.11.11.37", "state": "confirmed_responder"}
        ],
        "discovery_evidence_status": {"status": "available"},
        "discovery_evidence": {
            "devices": [
                {
                    "protocol": "lldp",
                    "source_mac": "00:11:22:33:44:55",
                    "addresses": ["10.11.11.37"],
                    "names": ["pcap-switch"],
                    "roles": ["network-neighbor"],
                }
            ],
            "cdp": {"devices": []},
            "lldp": {"devices": [{"name": "pcap-switch"}]},
            "mndp": {"devices": []},
        },
    }


def _services():
    return SimpleNamespace(
        inventory=SimpleNamespace(latest_scope=lambda _audit_id: None),
        jobs=SimpleNamespace(
            get_audit=lambda _audit_id: SimpleNamespace(
                scope={"targets": ["10.11.11.0/24"]},
                interface="ens37",
            )
        ),
    )


@pytest.mark.parametrize(
    ("status", "expected_reason"),
    [
        ("partial", "partial_observation_domain"),
        ("insufficient_evidence", "insufficient_observation_domain"),
        ("different_domain", "different_observation_domain"),
    ],
)
def test_unconfirmed_domain_keeps_pcap_as_evidence_without_mutating_structural_identity(
    monkeypatch,
    status,
    expected_reason,
):
    monkeypatch.setattr(
        traffic_overlay,
        "_load_document",
        lambda _services, _job_id: _document(),
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
            "status": status,
            "confidence": "low",
            "matches": {
                "exact_ips": [],
                "exact_macs": [],
                "ip_mac_conflicts": [],
            },
            "reasons": ["test status"],
        },
    )
    topology = {
        "overlay": {
            "traffic_analysis_job_id": "pcap-job",
            "interface": "ens37",
        },
        "nodes": [
            {
                "id": "asset:current",
                "kind": "asset",
                "label": "10.11.11.37",
                "addresses": ["10.11.11.37"],
                "mac": "00:11:22:33:44:55",
                "roles": [],
                "provenance": ["inventory"],
            }
        ],
        "edges": [],
        "warnings": [],
    }

    result = traffic_overlay.decorate_traffic_overlay(
        _services(),
        "audit-1",
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    assert len(result["nodes"]) == 1
    current = result["nodes"][0]
    assert current["kind"] == "asset"
    assert current["roles"] == []
    assert current["provenance"] == ["inventory"]
    assert "pcap_state" not in current
    assert "pcap_local_identity" not in current

    enrichment = result["overlay"]["topology_enrichment"]
    assert enrichment["allowed"] is False
    assert enrichment["reason"] == expected_reason
    assert enrichment["endpoint_annotation_applied"] is False
    assert enrichment["discovery_nodes_added"] == 0

    discovery = result["overlay"]["discovery"]
    assert discovery["device_count"] == 1
    assert discovery["topology_nodes_added"] == 0
    assert discovery["topology_enrichment_skipped"] is True
    assert discovery["topology_enrichment_skip_reason"] == expected_reason
    assert result["warnings"]


def test_compatible_domain_allows_endpoint_and_discovery_enrichment(monkeypatch):
    monkeypatch.setattr(
        traffic_overlay,
        "_load_document",
        lambda _services, _job_id: _document(),
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
            "status": "compatible",
            "confidence": "high",
            "matches": {
                "exact_ips": ["10.11.11.37"],
                "exact_macs": ["00:11:22:33:44:55"],
                "ip_mac_conflicts": [],
            },
            "reasons": ["exact identity"],
        },
    )
    topology = {
        "overlay": {
            "traffic_analysis_job_id": "pcap-job",
            "interface": "ens37",
        },
        "nodes": [
            {
                "id": "asset:current",
                "kind": "asset",
                "label": "10.11.11.37",
                "addresses": ["10.11.11.37"],
                "mac": "00:11:22:33:44:55",
                "roles": [],
                "provenance": ["inventory"],
            }
        ],
        "edges": [],
        "warnings": [],
    }

    result = traffic_overlay.decorate_traffic_overlay(
        _services(),
        "audit-1",
        topology,
        traffic_analysis_job_id="pcap-job",
    )

    current = result["nodes"][0]
    assert current["pcap_state"] == "confirmed_responder"
    assert current["pcap_local_identity"] is True
    assert current["kind"] == "network-device"
    assert "network-device" in current["roles"]
    assert "pcap-discovery" in current["provenance"]
    assert result["overlay"]["topology_enrichment"]["allowed"] is True
    assert result["overlay"]["topology_enrichment"]["status"] == "allowed"
    assert result["overlay"]["discovery"]["topology_enrichment_skipped"] is False
