from traffic_analysis.domain import assess_observation_domain


def _asset(address: str, mac: str | None = None) -> dict:
    return {"id": address, "addresses": [address], "mac": mac, "names": []}


def _traffic(
    candidates: list[dict],
    *,
    interface: str = "Vlan4",
    hints: list[str] | None = None,
) -> dict:
    return {
        "source": {"interface": interface},
        "identity_resolution": {"candidates": candidates},
        "observation_domain": {
            "private_ipv4_prefix_hints": [
                {"prefix": prefix, "frames": 10, "confidence": "hint"}
                for prefix in (hints or [])
            ]
        },
    }


def test_exact_mac_makes_domains_compatible_even_when_ip_changed():
    result = assess_observation_domain(
        assets=[_asset("10.11.11.37", "28:58:74:26:c4:60")],
        confirmed_scope={"targets": ["10.11.11.0/24"]},
        audit_scope={},
        audit_interface="ens37",
        traffic_document=_traffic(
            [
                {
                    "candidate_id": "mac:28:58:74:26:c4:60",
                    "status": "resolved",
                    "confidence": "high",
                    "addresses": ["10.0.18.229"],
                    "mac": "28:58:74:26:c4:60",
                    "basis": "mac_identity",
                }
            ],
            interface="Vlan4",
            hints=["10.0.18.0/24"],
        ),
    )

    assert result["status"] == "compatible"
    assert result["confidence"] == "high"
    assert result["matches"]["exact_macs"] == ["28:58:74:26:c4:60"]
    assert result["direct_correlation_recommended"] is True


def test_different_scopes_are_reported_as_different_domain_not_failed_correlation():
    result = assess_observation_domain(
        assets=[
            _asset("10.11.11.11"),
            _asset("10.11.11.37"),
            _asset("10.11.11.62"),
        ],
        confirmed_scope={"targets": ["10.11.11.0/24"]},
        audit_scope={},
        audit_interface="ens37",
        traffic_document=_traffic(
            [
                {
                    "candidate_id": "mac:00:11:22:33:44:55",
                    "status": "resolved",
                    "confidence": "high",
                    "addresses": ["10.0.18.229"],
                    "mac": "00:11:22:33:44:55",
                    "basis": "mac_identity",
                },
                {
                    "candidate_id": "mac:00:11:22:33:44:66",
                    "status": "resolved",
                    "confidence": "high",
                    "addresses": ["10.0.0.1"],
                    "mac": "00:11:22:33:44:66",
                    "basis": "mac_identity",
                },
            ],
            interface="Vlan4",
            hints=["10.0.18.0/24", "10.0.0.0/24"],
        ),
    )

    assert result["status"] == "different_domain"
    assert result["direct_correlation_recommended"] is False
    assert result["suppress_zero_correlation_warning"] is True
    assert result["matches"]["exact_ips"] == []
    assert result["matches"]["exact_macs"] == []
    assert result["matches"]["pcap_candidates_in_scope"] == []


def test_candidate_inside_confirmed_scope_is_compatible():
    result = assess_observation_domain(
        assets=[_asset("10.11.11.37")],
        confirmed_scope={"targets": ["10.11.11.0/24"]},
        audit_scope={},
        audit_interface="ens37",
        traffic_document=_traffic(
            [
                {
                    "candidate_id": "mac:00:11:22:33:44:55",
                    "status": "resolved",
                    "confidence": "high",
                    "addresses": ["10.11.11.124"],
                    "mac": "00:11:22:33:44:55",
                    "basis": "mac_identity",
                }
            ],
            interface="ens37",
            hints=["10.11.11.0/24"],
        ),
    )

    assert result["status"] == "compatible"
    assert result["matches"]["pcap_candidates_in_scope"] == ["10.11.11.124"]


def test_same_private_ip_with_different_known_mac_is_not_compatible_identity_evidence():
    result = assess_observation_domain(
        assets=[_asset("10.11.11.37", "00:11:22:33:44:55")],
        confirmed_scope={"targets": ["10.11.11.0/24"]},
        audit_scope={},
        audit_interface="ens37",
        traffic_document=_traffic(
            [
                {
                    "candidate_id": "mac:66:77:88:99:aa:bb",
                    "status": "resolved",
                    "confidence": "high",
                    "addresses": ["10.11.11.37"],
                    "mac": "66:77:88:99:aa:bb",
                    "basis": "mac_identity",
                }
            ],
            interface="ens37",
            hints=["10.11.11.0/24"],
        ),
    )

    assert result["status"] == "partial"
    assert result["matches"]["exact_ips"] == []
    assert result["matches"]["raw_ip_overlaps"] == ["10.11.11.37"]
    assert result["matches"]["exact_macs"] == []
    assert result["matches"]["pcap_candidates_in_scope"] == []
    assert result["matches"]["ip_mac_conflicts"] == [
        {
            "ip": "10.11.11.37",
            "inventory_macs": ["00:11:22:33:44:55"],
            "pcap_macs": ["66:77:88:99:aa:bb"],
            "reason": "IP совпал, но известные MAC различаются; IP reuse не считается доказательством общего observation domain.",
        }
    ]
    assert any("IP/MAC конфликтов: 1" in reason for reason in result["reasons"])


def test_probe_targets_do_not_make_domains_compatible():
    result = assess_observation_domain(
        assets=[_asset("10.11.11.37")],
        confirmed_scope={"targets": ["10.11.11.0/24"]},
        audit_scope={},
        audit_interface="ens37",
        traffic_document={
            "source": {"interface": "ens37"},
            "identity_resolution": {"candidates": []},
            "endpoint_evidence": [
                {"endpoint": "10.11.11.37", "state": "probed_target"},
            ],
            "observation_domain": {"private_ipv4_prefix_hints": []},
        },
    )

    assert result["status"] == "insufficient_evidence"
    assert result["matches"]["exact_ips"] == []
