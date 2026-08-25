from topology.history import compare_topology_history


def test_history_diff_warns_when_baseline_topology_is_partial():
    baseline = {
        "audit": {"id": "audit-old"},
        "nodes": [],
        "edges": [],
        "segments": [],
        "partial": True,
        "source_errors": [
            {
                "audit_id": "audit-old",
                "artifact_id": "broken-snmp",
                "component": "snmp-topology",
                "code": "artifact_unavailable",
            }
        ],
    }
    current = {
        "audit": {"id": "audit-new"},
        "nodes": [],
        "edges": [],
        "segments": [],
        "partial": False,
        "source_errors": [],
    }

    result = compare_topology_history(baseline=baseline, current=current)

    assert result["partial"] is True
    assert result["baseline"]["partial"] is True
    assert result["baseline"]["source_error_count"] == 1
    assert result["current"]["partial"] is False
    assert result["current"]["source_error_count"] == 0
    assert result["summary"]["baseline_source_errors"] == 1
    assert result["summary"]["current_source_errors"] == 0
    assert any("Базовая topology неполная" in warning for warning in result["warnings"])
