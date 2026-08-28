from traffic_analysis.gateway import derive_next_hop_evidence


def test_private_host_using_one_strong_mac_for_many_external_destinations_yields_next_hop():
    document = {
        "identity_observations": {
            "links": [
                {
                    "ip": "10.0.0.1",
                    "mac": "a8:f9:4b:2e:02:80",
                    "confidence": "high",
                    "evidence": [{"type": "arp_reply_sender", "count": 7}],
                }
            ]
        },
        "directional_flows": [
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "20.201.1.37",
                "src_mac": "d4:9c:53:13:b4:b2",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 10,
                "bytes": 1000,
                "protocols": [{"name": "tls", "frames": 10}],
            },
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "31.135.14.238",
                "src_mac": "d4:9c:53:13:b4:b2",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 20,
                "bytes": 2000,
                "protocols": [{"name": "tls", "frames": 20}],
            },
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "37.9.54.204",
                "src_mac": "d4:9c:53:13:b4:b2",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 30,
                "bytes": 3000,
                "protocols": [{"name": "quic", "frames": 30}],
            },
        ],
    }

    result = derive_next_hop_evidence(document)

    assert result["candidate_count"] == 1
    assert result["high_confidence_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["source_ip"] == "10.0.18.229"
    assert candidate["next_hop_ip"] == "10.0.0.1"
    assert candidate["next_hop_mac"] == "a8:f9:4b:2e:02:80"
    assert candidate["remote_destination_count"] == 3
    assert candidate["flow_count"] == 3
    assert candidate["bytes"] == 6000
    assert candidate["relation"] == "l3_next_hop"


def test_destination_mac_without_strong_identity_is_not_promoted_to_gateway():
    document = {
        "identity_observations": {
            "links": [
                {
                    "ip": "10.0.0.1",
                    "mac": "a8:f9:4b:2e:02:80",
                    "confidence": "medium",
                    "evidence": [{"type": "ethernet_ip_source", "count": 10}],
                }
            ]
        },
        "directional_flows": [
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "20.201.1.37",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 10,
                "bytes": 1000,
            },
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "31.135.14.238",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 10,
                "bytes": 1000,
            },
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "37.9.54.204",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 10,
                "bytes": 1000,
            },
        ],
    }

    result = derive_next_hop_evidence(document)
    assert result["candidate_count"] == 0


def test_ambiguous_strong_mac_mapping_is_retained_as_ambiguity_not_gateway():
    document = {
        "identity_observations": {
            "links": [
                {
                    "ip": "10.0.0.1",
                    "mac": "a8:f9:4b:2e:02:80",
                    "confidence": "high",
                    "evidence": [{"type": "arp_reply_sender", "count": 2}],
                },
                {
                    "ip": "10.0.0.254",
                    "mac": "a8:f9:4b:2e:02:80",
                    "confidence": "high",
                    "evidence": [{"type": "mndp_advertisement", "count": 2}],
                },
            ]
        },
        "directional_flows": [
            {
                "src_ip": "10.0.18.229",
                "dst_ip": "20.201.1.37",
                "dst_mac": "a8:f9:4b:2e:02:80",
                "packets": 10,
                "bytes": 1000,
            }
        ],
    }

    result = derive_next_hop_evidence(document)
    assert result["candidate_count"] == 0
    assert result["ambiguous"][0]["candidate_ips"] == ["10.0.0.1", "10.0.0.254"]
