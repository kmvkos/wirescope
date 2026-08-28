from traffic_analysis.identity import build_identity_candidates


def test_identity_resolver_excludes_probe_and_external_and_keeps_conflicts():
    document = {
        "identity_observations": {
            "links": [
                {
                    "ip": "10.0.0.10",
                    "mac": "00:11:22:33:44:10",
                    "confidence": "high",
                    "evidence": [{"type": "arp_reply_sender", "count": 3}],
                },
                {
                    "ip": "10.0.0.20",
                    "mac": "00:11:22:33:44:20",
                    "confidence": "medium",
                    "evidence": [{"type": "ethernet_ip_source", "count": 8}],
                },
                {
                    "ip": "10.0.0.30",
                    "mac": "00:11:22:33:44:30",
                    "confidence": "high",
                    "evidence": [{"type": "arp_reply_sender", "count": 1}],
                },
                {
                    "ip": "10.0.0.30",
                    "mac": "00:11:22:33:44:31",
                    "confidence": "high",
                    "evidence": [{"type": "arp_reply_sender", "count": 1}],
                },
                {
                    "ip": "198.51.100.10",
                    "mac": "00:aa:bb:cc:dd:ee",
                    "confidence": "medium",
                    "evidence": [{"type": "ethernet_ip_source", "count": 4}],
                },
            ]
        },
        "endpoint_evidence": [
            {"endpoint": "10.0.0.10", "state": "confirmed_responder"},
            {"endpoint": "10.0.0.20", "state": "observed_sender"},
            {"endpoint": "10.0.0.30", "state": "confirmed_responder"},
            {"endpoint": "10.0.0.99", "state": "probed_target"},
            {"endpoint": "198.51.100.10", "state": "external_peer"},
            {"endpoint": "10.0.0.40", "state": "observed_sender"},
            {"endpoint": "10.0.0.50", "state": "observed_peer"},
        ],
    }

    result = build_identity_candidates(document)
    by_id = {item["candidate_id"]: item for item in result["candidates"]}

    assert by_id["mac:00:11:22:33:44:10"]["status"] == "resolved"
    assert by_id["mac:00:11:22:33:44:20"]["status"] == "provisional"
    assert by_id["mac:00:11:22:33:44:30"]["status"] == "conflict"
    assert by_id["mac:00:11:22:33:44:31"]["status"] == "conflict"
    assert by_id["ip:10.0.0.40"]["status"] == "provisional"

    candidate_addresses = {
        address
        for item in result["candidates"]
        for address in item.get("addresses") or []
    }
    assert "10.0.0.99" not in candidate_addresses
    assert "198.51.100.10" not in candidate_addresses
    assert "10.0.0.50" not in candidate_addresses

    assert result["conflict_count"] == 2
    assert result["conflicts"] == [
        {
            "ip": "10.0.0.30",
            "macs": ["00:11:22:33:44:30", "00:11:22:33:44:31"],
            "reason": "multiple_mac_claims",
        }
    ]
