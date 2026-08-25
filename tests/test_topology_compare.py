from topology.compare import compare_topologies


def _topology(*, audit_id: str, host_id: str, host_vlan: int, port_name: str, extra: bool = False):
    nodes = [
        {
            "id": f"asset:{host_id}",
            "kind": "asset",
            "label": "server-01",
            "asset_id": host_id,
            "mac": "00:11:22:33:44:55",
            "addresses": ["10.0.0.10"],
            "names": ["server-01"],
            "roles": [],
            "vlan_ids": [host_vlan],
            "segment_ids": ["segment:10.0.0.0/24"],
            "confidence": "confirmed",
        },
        {
            "id": "snmp-device:10.0.0.1",
            "kind": "network-device",
            "label": "core-sw",
            "addresses": ["10.0.0.1"],
            "roles": ["network-device", "snmp-managed"],
            "confidence": "observed",
        },
        {
            "id": "group:224.0.0.251",
            "kind": "multicast-group",
            "label": "224.0.0.251",
            "addresses": ["224.0.0.251"],
        },
    ]
    if extra:
        nodes.append(
            {
                "id": "endpoint:10.0.0.77",
                "kind": "endpoint",
                "label": "10.0.0.77",
                "addresses": ["10.0.0.77"],
                "roles": [],
                "confidence": "observed",
            }
        )
    return {
        "audit": {
            "id": audit_id,
            "profile": "deep",
            "interface": "eth0",
            "status": "completed",
        },
        "nodes": nodes,
        "segments": [
            {
                "id": "segment:10.0.0.0/24",
                "network": "10.0.0.0/24",
                "members": [f"asset:{host_id}"],
            }
        ],
        "edges": [
            {
                "id": f"edge:{audit_id}",
                "source": "snmp-device:10.0.0.1",
                "target": f"asset:{host_id}",
                "relation": "layer2_neighbor",
                "mapping_type": "switch_port",
                "confidence": "observed",
                "provenance": ["credentialed-snmp"],
                "port_name": port_name,
                "vlan_ids": [host_vlan],
            }
        ],
    }


def test_historical_diff_matches_asset_by_mac_not_audit_local_asset_id():
    baseline = _topology(
        audit_id="audit-old",
        host_id="uuid-old",
        host_vlan=10,
        port_name="Gi1/0/5",
    )
    current = _topology(
        audit_id="audit-new",
        host_id="uuid-new",
        host_vlan=20,
        port_name="Gi1/0/8",
        extra=True,
    )

    result = compare_topologies(baseline=baseline, current=current)

    assert result["schema"] == "network-topology-diff"
    assert result["baseline"]["audit_id"] == "audit-old"
    assert result["current"]["audit_id"] == "audit-new"
    assert result["summary"]["nodes_added"] == 1
    assert result["summary"]["nodes_removed"] == 0
    assert result["summary"]["nodes_changed"] == 1
    assert result["summary"]["edges_added"] == 0
    assert result["summary"]["edges_removed"] == 0
    assert result["summary"]["edges_changed"] == 1
    assert result["summary"]["ignored_unstable_nodes"] == 2

    changed = result["nodes"]["changed"][0]
    assert changed["key"] == "mac:00:11:22:33:44:55"
    assert changed["match_basis"] == "mac"
    assert changed["changes"]["vlan_ids"] == {"before": [10], "after": [20]}
    assert all("uuid-old" not in item["key"] for item in result["nodes"]["removed"])
    assert result["nodes"]["added"][0]["key"] == "ip:10.0.0.77"

    edge = result["edges"]["changed"][0]
    assert edge["changes"]["port_name"] == {"before": "Gi1/0/5", "after": "Gi1/0/8"}
    assert edge["changes"]["vlan_ids"] == {"before": [10], "after": [20]}


def test_hostname_alone_never_correlates_nodes_across_audits():
    baseline = {
        "audit": {"id": "old"},
        "nodes": [
            {
                "id": "asset:old-id",
                "kind": "asset",
                "label": "printer-01",
                "names": ["printer-01"],
                "addresses": [],
            }
        ],
        "edges": [],
        "segments": [],
    }
    current = {
        "audit": {"id": "new"},
        "nodes": [
            {
                "id": "asset:new-id",
                "kind": "asset",
                "label": "printer-01",
                "names": ["printer-01"],
                "addresses": [],
            }
        ],
        "edges": [],
        "segments": [],
    }

    result = compare_topologies(baseline=baseline, current=current)

    assert result["summary"]["nodes_changed"] == 0
    assert result["summary"]["nodes_removed"] == 1
    assert result["summary"]["nodes_added"] == 1
    assert result["nodes"]["removed"][0]["match_basis"] == "opaque"
    assert result["nodes"]["added"][0]["match_basis"] == "opaque"


def test_segment_changes_are_reported_separately():
    baseline = {
        "audit": {"id": "old"},
        "nodes": [],
        "edges": [],
        "segments": [{"network": "10.10.10.0/24"}],
    }
    current = {
        "audit": {"id": "new"},
        "nodes": [],
        "edges": [],
        "segments": [{"network": "10.20.20.0/24"}],
    }

    result = compare_topologies(baseline=baseline, current=current)

    assert result["segments"] == {
        "added": ["10.20.20.0/24"],
        "removed": ["10.10.10.0/24"],
    }
    assert result["summary"]["segments_added"] == 1
    assert result["summary"]["segments_removed"] == 1
