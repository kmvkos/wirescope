from global_analysis import assemble_global_analysis
from global_analysis.enrich import enrich_global_analysis
from global_analysis.render import render_markdown, render_text


def _document():
    traffic = {
        "schema": "traffic-analysis",
        "schema_version": 1,
        "analyzer_version": 6,
        "summary": {"frame_count": 500, "duration_seconds": 45},
        "communications_graph": {
            "nodes": [
                {"id": "10.0.0.10", "kind": "ip"},
                {"id": "10.0.0.50", "kind": "ip"},
            ],
            "edges": [
                {
                    "endpoint_a": "10.0.0.10",
                    "endpoint_b": "10.0.0.50",
                    "packets": 40,
                    "bytes": 7000,
                    "protocols": [{"name": "telnet", "frames": 30}],
                    "ports": [{"port": "tcp/23", "frames": 30}],
                    "confidence": "observed",
                }
            ],
        },
        "protocol_intelligence": {
            "dns": {"servers": [{"endpoint": "10.0.0.53"}]},
            "dhcp": {"servers": []},
        },
    }
    topology = {
        "schema": "network-topology",
        "schema_version": 3,
        "partial": True,
        "segments": [{"network": "10.0.0.0/24"}],
        "nodes": [],
        "coverage": {
            "inventory": {"status": "sufficient"},
            "l2": {"status": "partial"},
            "l3": {"status": "sufficient"},
        },
    }
    base = assemble_global_analysis(
        audit={"id": "audit-1", "profile": "deep", "interface": "eth0", "status": "completed"},
        assets=[
            {"id": "server", "state": "responsive", "mac": "00:11:22:33:44:10", "addresses": ["10.0.0.10"]},
            {"id": "unused", "state": "responsive", "mac": "00:11:22:33:44:99", "addresses": ["10.0.0.99"]},
        ],
        services=[
            {"id": "svc-telnet", "asset_id": "server", "protocol": "tcp", "port": 23, "state": "open"},
            {"id": "svc-http", "asset_id": "unused", "protocol": "tcp", "port": 8080, "state": "open"},
        ],
        findings=[
            {"id": "finding-unused", "asset_id": "unused", "service_id": "svc-http", "severity": "medium", "status": "open"}
        ],
        traffic_job={"id": "traffic-1", "audit_id": "capture-1", "result_reference": "artifact-traffic"},
        traffic_analysis=traffic,
        topology=topology,
    )
    return enrich_global_analysis(
        base,
        environment={
            "default_routes": [{"interface": "eth0", "gateway": "10.0.0.1"}],
            "dns": ["10.0.0.53"],
            "dhcp_leases": [],
        },
        passive={"dhcp": {"routers": [], "servers": []}},
        topology=topology,
        traffic_analysis=traffic,
        evidence_references=[],
    )


def test_evidence_gaps_explain_what_is_missing_and_how_to_collect_it():
    document = _document()
    gaps = document["evidence_gaps"]
    categories = {row["category"] for row in gaps}

    assert "infrastructure_gateway" in categories
    assert "infrastructure_dhcp" not in categories
    assert "service_direction" in categories
    assert "service_visibility" in categories
    assert "finding_corroboration" in categories
    assert "capture_visibility" in categories
    assert "unmatched_internal_endpoints" in categories
    assert "topology_coverage" in categories

    gateway = next(row for row in gaps if row["category"] == "infrastructure_gateway")
    assert gateway["status"] == "needs_evidence"
    assert gateway["known_evidence"]
    assert gateway["missing_evidence"]
    assert gateway["collection_options"]
    assert gateway["safe_conclusion"]

    service = next(row for row in gaps if row["category"] == "service_direction")
    assert "SYN/SYN-ACK" in " ".join(service["collection_options"])
    assert "нельзя утверждать" in service["safe_conclusion"]

    assert document["summary"]["evidence_gaps"] == len(gaps)
    assert document["summary"]["evidence_gaps_high"] >= 1
    assert document["summary"]["evidence_status"] == "needs_evidence"
    assert any("как это собрать" in line for line in document["operator_summary"]["lines"])
    assert not any(
        "dhcp" in line.lower() and "недостаточно независимых источников" in line.lower()
        for line in document["operator_summary"]["lines"]
    )


def test_evidence_gap_ids_are_stable_for_same_persisted_evidence():
    first = _document()
    second = _document()
    assert [(row["category"], row["id"]) for row in first["evidence_gaps"]] == [
        (row["category"], row["id"]) for row in second["evidence_gaps"]
    ]


def test_human_exports_put_missing_evidence_before_low_level_sections():
    document = _document()
    text = render_text(document)
    markdown = render_markdown(document)

    assert "ЧЕГО НЕ ХВАТАЕТ ДЛЯ БОЛЕЕ СИЛЬНЫХ ВЫВОДОВ" in text
    assert "Что уже есть:" in text
    assert "Чего не хватает:" in text
    assert "Как добрать данные:" in text
    assert "Пока корректно утверждать:" in text
    assert text.index("ЧЕГО НЕ ХВАТАЕТ") < text.index("СВОДКА СОПОСТАВЛЕНИЯ")

    assert "## Чего не хватает для более сильных выводов" in markdown
    assert "**Как добрать данные:**" in markdown
    assert "**Пока корректно утверждать:**" in markdown
