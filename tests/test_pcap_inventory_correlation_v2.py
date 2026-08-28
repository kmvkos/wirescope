from traffic_analysis.correlation_v2 import correlate_inventory_with_pcap


def _compat(status: str) -> dict:
    return {"status": status}


def test_exact_mac_correlates_even_when_ip_changed():
    result = correlate_inventory_with_pcap(
        assets=[
            {
                "id": "asset-1",
                "mac": "28:58:74:26:c4:60",
                "addresses": ["10.11.11.37"],
                "names": ["host-a"],
            }
        ],
        traffic_document={
            "identity_resolution": {
                "candidates": [
                    {
                        "candidate_id": "mac:28:58:74:26:c4:60",
                        "status": "resolved",
                        "confidence": "high",
                        "mac": "28:58:74:26:c4:60",
                        "addresses": ["10.0.18.229"],
                    }
                ]
            }
        },
        compatibility=_compat("compatible"),
    )

    assert result["status"] == "matched"
    assert result["matched_asset_count"] == 1
    match = result["matches"][0]
    assert match["basis"] == "exact_mac"
    assert match["confidence"] == "high"
    assert "изменившемся IP" in match["reason"]


def test_exact_ip_with_conflicting_mac_is_not_merged():
    result = correlate_inventory_with_pcap(
        assets=[
            {
                "id": "asset-1",
                "mac": "00:11:22:33:44:55",
                "addresses": ["10.0.0.10"],
                "names": [],
            }
        ],
        traffic_document={
            "identity_resolution": {
                "candidates": [
                    {
                        "candidate_id": "mac:00:11:22:33:44:66",
                        "status": "resolved",
                        "confidence": "high",
                        "mac": "00:11:22:33:44:66",
                        "addresses": ["10.0.0.10"],
                    }
                ]
            }
        },
        compatibility=_compat("compatible"),
    )

    assert result["status"] == "conflict"
    assert result["matched_asset_count"] == 0
    conflict = result["conflicts"][0]
    assert conflict["type"] == "ip_match_mac_conflict"
    assert conflict["inventory_mac"] != conflict["pcap_mac"]


def test_name_only_is_weak_and_never_auto_merges():
    result = correlate_inventory_with_pcap(
        assets=[
            {
                "id": "asset-1",
                "mac": None,
                "addresses": ["10.0.0.10"],
                "names": ["access-sw-1"],
            }
        ],
        traffic_document={
            "identity_resolution": {
                "candidates": [
                    {
                        "candidate_id": "mac:00:11:22:33:44:55",
                        "status": "resolved",
                        "confidence": "high",
                        "mac": "00:11:22:33:44:55",
                        "addresses": ["10.0.0.20"],
                    }
                ]
            },
            "discovery_evidence": {
                "devices": [
                    {
                        "protocol": "lldp",
                        "source_mac": "00:11:22:33:44:55",
                        "addresses": ["10.0.0.20"],
                        "names": ["access-sw-1"],
                    }
                ],
                "dhcp": {"assignments": []},
            },
        },
        compatibility=_compat("compatible"),
    )

    assert result["matched_asset_count"] == 0
    assert result["status"] == "no_exact_match"
    weak = result["weak_observations"][0]
    assert weak["type"] == "name_only"
    assert weak["shared_names"] == ["access-sw-1"]


def test_different_domain_skips_correlation_and_does_not_report_unmatched_failure():
    result = correlate_inventory_with_pcap(
        assets=[
            {"id": "asset-1", "mac": None, "addresses": ["10.11.11.37"], "names": []},
            {"id": "asset-2", "mac": None, "addresses": ["10.11.11.62"], "names": []},
        ],
        traffic_document={
            "identity_resolution": {
                "candidates": [
                    {
                        "candidate_id": "mac:00:11:22:33:44:55",
                        "status": "resolved",
                        "confidence": "high",
                        "mac": "00:11:22:33:44:55",
                        "addresses": ["10.0.18.229"],
                    }
                ]
            }
        },
        compatibility=_compat("different_domain"),
    )

    assert result["status"] == "skipped_different_domain"
    assert result["correlation_attempted"] is False
    assert result["matches"] == []
    assert result["unmatched_inventory_assets"] == []
    assert result["unmatched_pcap_candidates"] == []
