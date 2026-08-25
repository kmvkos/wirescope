from types import SimpleNamespace

from topology.findings import attach_findings


def test_attach_findings_projects_only_matching_assets_and_bounds_node_payload():
    topology = {
        "nodes": [
            {"id": "asset:a", "kind": "asset", "asset_id": "a"},
            {"id": "asset:b", "kind": "asset", "asset_id": "b"},
            {"id": "endpoint:8.8.8.8", "kind": "endpoint"},
        ]
    }
    rows = [
        SimpleNamespace(
            id=f"finding-{index}",
            rule_id="demo.rule",
            title=f"Finding {index}",
            severity=SimpleNamespace(value="high" if index == 0 else "low"),
            confidence=SimpleNamespace(value="confirmed"),
            status=SimpleNamespace(value="open"),
            asset_id="a",
            service_id=None,
            description="Observed issue",
            recommendation="Fix it",
        )
        for index in range(35)
    ]
    rows.append(
        SimpleNamespace(
            id="finding-b",
            rule_id="demo.other",
            title="Other asset",
            severity=SimpleNamespace(value="medium"),
            confidence=SimpleNamespace(value="observed"),
            status=SimpleNamespace(value="suppressed"),
            asset_id="b",
            service_id="svc-b",
            description="Other issue",
            recommendation="Review",
        )
    )
    rows.append(
        SimpleNamespace(
            id="finding-unbound",
            rule_id="demo.audit",
            title="Audit-level finding",
            severity=SimpleNamespace(value="low"),
            confidence=SimpleNamespace(value="observed"),
            status=SimpleNamespace(value="open"),
            asset_id=None,
            service_id=None,
            description="No asset",
            recommendation="Review audit",
        )
    )

    attach_findings(topology, rows, total=len(rows))

    by_id = {node["id"]: node for node in topology["nodes"]}
    assert by_id["asset:a"]["finding_count"] == 35
    assert len(by_id["asset:a"]["findings"]) == 32
    assert by_id["asset:a"]["findings_truncated"] is True
    assert by_id["asset:a"]["findings"][0]["severity"] == "high"

    assert by_id["asset:b"]["finding_count"] == 1
    assert by_id["asset:b"]["findings"][0]["service_id"] == "svc-b"
    assert by_id["endpoint:8.8.8.8"].get("findings") is None

    summary = topology["finding_summary"]
    assert summary["total"] == 37
    assert summary["projected_to_assets"] == 36
    assert summary["nodes_with_findings"] == 2
    assert summary["truncated_nodes"] == 1
    assert summary["severity"] == {"high": 1, "low": 34, "medium": 1}
