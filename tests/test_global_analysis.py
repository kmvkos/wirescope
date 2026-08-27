from global_analysis import assemble_global_analysis
from tests.helpers import http_request as request


def _sample_analysis():
    return assemble_global_analysis(
        audit={
            "id": "audit-deep",
            "profile": "deep",
            "interface": "ens37",
            "status": "completed",
        },
        assets=[
            {
                "id": "server",
                "state": "responsive",
                "mac": "00:11:22:33:44:10",
                "addresses": ["10.0.0.10"],
                "names": ["server01"],
            },
            {
                "id": "router",
                "state": "responsive",
                "mac": "00:11:22:33:44:01",
                "addresses": ["10.0.0.1"],
                "names": ["gw01"],
            },
            {
                "id": "unused",
                "state": "responsive",
                "mac": "00:11:22:33:44:99",
                "addresses": ["10.0.0.99"],
                "names": ["unused01"],
            },
        ],
        services=[
            {
                "id": "svc-https",
                "asset_id": "server",
                "protocol": "tcp",
                "port": 443,
                "state": "open",
            },
            {
                "id": "svc-ssh",
                "asset_id": "router",
                "protocol": "tcp",
                "port": 22,
                "state": "open",
            },
            {
                "id": "svc-unused",
                "asset_id": "unused",
                "protocol": "tcp",
                "port": 8080,
                "state": "open",
            },
        ],
        findings=[
            {
                "id": "finding-service",
                "asset_id": "server",
                "service_id": "svc-https",
                "severity": "medium",
                "status": "open",
            },
            {
                "id": "finding-unused",
                "asset_id": "unused",
                "service_id": None,
                "severity": "low",
                "status": "open",
            },
        ],
        traffic_job={
            "id": "traffic-1",
            "audit_id": "capture-audit",
            "result_reference": "artifact-traffic",
        },
        traffic_analysis={
            "schema": "traffic-analysis",
            "schema_version": 1,
            "analyzer_version": 5,
            "summary": {
                "frame_count": 1200,
                "duration_seconds": 60,
            },
            "communications_graph": {
                "nodes": [
                    {"id": "10.0.0.10", "kind": "ip"},
                    {"id": "8.8.8.8", "kind": "ip"},
                    {"id": "00:11:22:33:44:01", "kind": "mac"},
                    {"id": "192.168.50.50", "kind": "ip"},
                    {"id": "server01", "kind": "name"},
                ],
                "edges": [
                    {
                        "endpoint_a": "10.0.0.10",
                        "endpoint_b": "8.8.8.8",
                        "packets": 120,
                        "bytes": 45000,
                        "protocols": [{"name": "tls", "frames": 100}],
                        "ports": [{"port": "tcp/443", "frames": 100}],
                        "confidence": "observed",
                    },
                    {
                        "endpoint_a": "00:11:22:33:44:01",
                        "endpoint_b": "192.168.50.50",
                        "packets": 20,
                        "bytes": 6000,
                        "protocols": [{"name": "ssh", "frames": 20}],
                        "ports": [{"port": "tcp/22", "frames": 12}],
                        "confidence": "observed",
                    },
                ],
            },
        },
        topology={
            "schema": "network-topology",
            "schema_version": 3,
            "partial": False,
            "segments": [
                {"network": "10.0.0.0/24"},
            ],
            "coverage": {
                "inventory": {"status": "sufficient"},
                "l3": {"status": "sufficient"},
                "l2": {"status": "partial"},
            },
        },
    )


def test_global_analysis_matches_asset_identity_only_by_exact_ip_or_mac():
    data = _sample_analysis()
    identities = {row["endpoint"]: row for row in data["asset_traffic_identity"]}

    assert identities["10.0.0.10"]["asset_id"] == "server"
    assert identities["10.0.0.10"]["match_basis"] == "exact_ip"
    assert identities["00:11:22:33:44:01"]["asset_id"] == "router"
    assert identities["00:11:22:33:44:01"]["match_basis"] == "exact_mac"

    # A matching inventory hostname is deliberately not an identity key.
    assert identities["server01"]["asset_id"] is None
    assert identities["server01"]["match_basis"] == "unmatched"


def test_global_analysis_correlates_pair_level_service_usage_without_overclaiming_direction():
    data = _sample_analysis()
    usage = {row["service_id"]: row for row in data["service_usage"]}

    assert usage["svc-https"]["observed_in_selected_traffic"] is True
    assert usage["svc-https"]["match_basis"] == "observed_pair_destination_port"
    assert usage["svc-ssh"]["observed_in_selected_traffic"] is True
    assert usage["svc-unused"]["observed_in_selected_traffic"] is False
    assert any("pair-level" in warning for warning in data["warnings"])


def test_global_analysis_keeps_private_unknown_separate_from_external_global():
    data = _sample_analysis()

    assert len(data["external_communications"]) == 1
    external = data["external_communications"][0]
    assert external["asset_id"] == "server"
    assert external["external_endpoint"] == "8.8.8.8"

    assert len(data["unclassified_communications"]) == 1
    unknown = data["unclassified_communications"][0]
    assert unknown["asset_id"] == "router"
    assert unknown["endpoint"] == "192.168.50.50"


def test_global_analysis_reports_inventory_vs_capture_visibility_and_finding_relevance():
    data = _sample_analysis()
    assert data["summary"]["inventory_assets"] == 3
    assert data["summary"]["inventory_assets_observed_in_traffic"] == 2
    assert data["summary"]["inventory_assets_not_observed_in_traffic"] == 1

    missing = data["coverage"]["inventory_assets_not_observed"]
    assert [row["asset_id"] for row in missing] == ["unused"]

    relevance = {row["finding_id"]: row for row in data["finding_traffic_relevance"]}
    assert relevance["finding-service"]["traffic_relevance"] == "service_traffic_observed"
    assert relevance["finding-unused"]["traffic_relevance"] == "uncorrelated"


def test_global_analysis_ids_are_stable_across_rebuilds():
    first = _sample_analysis()
    second = _sample_analysis()

    assert [row["id"] for row in first["asset_traffic_identity"]] == [
        row["id"] for row in second["asset_traffic_identity"]
    ]
    assert [row["id"] for row in first["external_communications"]] == [
        row["id"] for row in second["external_communications"]
    ]


def test_global_analysis_inherits_partial_source_state():
    data = assemble_global_analysis(
        audit={"id": "a", "profile": "deep", "interface": "eth0", "status": "completed"},
        assets=[],
        services=[],
        findings=[],
        traffic_job={"id": "t", "audit_id": "c", "result_reference": "r"},
        traffic_analysis={
            "schema": "traffic-analysis",
            "communications_graph": {"nodes": [], "edges": []},
        },
        topology={
            "schema": "network-topology",
            "schema_version": 3,
            "partial": True,
            "segments": [],
            "coverage": {"l2": {"status": "missing"}},
        },
    )
    assert data["partial"] is True
    assert data["source_health"]["topology"] == "partial"
    assert data["coverage"]["topology"]["l2"]["status"] == "missing"


def test_global_analysis_api_requires_completed_selected_traffic_source(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={"targets": ["192.0.2.0/24"]},
        actor="auditor",
    )

    response = request(
        app,
        "GET",
        f"/api/v1/audits/{audit.id}/global-analysis?traffic_analysis_job_id=missing",
        as_role="viewer",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "global_analysis_source_invalid"
