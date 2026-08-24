from dataclasses import replace

from backend.dependencies import AppServices
from jobs.models import RetentionClass
from tests.helpers import http_request as request


def _create_audit(app, *, profile="standard"):
    response = request(
        app,
        "POST",
        "/api/v1/audits",
        json={
            "profile": profile,
            "interface": "eth0",
            "scope": {"site": "test"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_capabilities_and_scan_profile_catalog(api_context):
    app, _service, _evidence, _environment = api_context

    capabilities = request(app, "GET", "/api/v1/capabilities")
    profiles = request(app, "GET", "/api/v1/scan-profiles")

    assert capabilities.status_code == 200
    payload = capabilities.json()
    assert payload["core_ready"] is True
    assert {item["tool"] for item in payload["tools"]} >= {"dumpcap", "tshark", "nmap"}
    assert payload["features"]["audit_diff"] is True
    assert payload["features"]["markdown_report"] is True
    assert profiles.status_code == 200
    assert set(profiles.json()["profiles"]) == {"discovery", "standard", "deep"}


def test_dashboard_correlations_and_empty_diff(api_context):
    app, service, _evidence, _environment = api_context
    first = _create_audit(app)
    second = _create_audit(app)

    # Make pipeline state observable without executing network work.
    service.create_job(
        audit_id=second,
        job_type="findings_evaluation",
        target="eth0",
        parameters={},
        resource_key=f"audit:{second}",
        resource_group="findings",
        resource_limit=1,
    )

    dashboard = request(app, "GET", f"/api/v1/audits/{second}/dashboard")
    correlations = request(app, "GET", f"/api/v1/audits/{second}/correlations")
    diff = request(app, "GET", f"/api/v1/audits/{second}/diff", params={"against": first})

    assert dashboard.status_code == 200
    stages = {item["stage"]: item for item in dashboard.json()["pipeline"]}
    assert set(stages) == {"passive", "discovery", "protocol", "findings", "report"}
    assert stages["findings"]["status"] == "queued"
    assert correlations.status_code == 200
    assert correlations.json()["total_assets"] == 0
    assert diff.status_code == 200
    assert diff.json()["assets"] == {"added": [], "removed": []}
    assert diff.json()["services"] == {"added": [], "removed": []}
    assert diff.json()["findings"] == {"added": [], "removed": []}


def test_evidence_download_is_bound_to_audit(api_context):
    app, _service, evidence, _environment = api_context
    audit_id = _create_audit(app)
    other_audit_id = _create_audit(app)
    artifact = evidence.put_json(
        audit_id=audit_id,
        job_id=None,
        artifact_type="test_evidence",
        document={"hello": "world"},
        retention_class=RetentionClass.AUDIT,
        schema_name="test-evidence",
        schema_version=1,
    )

    own = request(app, "GET", f"/api/v1/audits/{audit_id}/artifacts/{artifact.id}")
    wrong = request(app, "GET", f"/api/v1/audits/{other_audit_id}/artifacts/{artifact.id}")

    assert own.status_code == 200
    assert own.json() == {"hello": "world"}
    assert own.headers["x-wirescope-sha256"] == artifact.sha256
    assert wrong.status_code == 404


def test_optional_nmap_does_not_control_readiness(api_context):
    app, service, _evidence, _environment = api_context
    service.register_worker("ready-without-nmap")
    service.heartbeat_worker("ready-without-nmap", status="idle")

    current: AppServices = app.state.services
    app.state.services = replace(
        current,
        settings=replace(current.settings, nmap_binary="definitely-not-installed-wirescope-test"),
    )

    ready = request(app, "GET", "/api/v1/ready")
    capabilities = request(app, "GET", "/api/v1/capabilities")

    assert ready.status_code == 200
    assert set(ready.json()["dependencies"]) == {"dumpcap", "tshark"}
    nmap = next(item for item in capabilities.json()["tools"] if item["tool"] == "nmap")
    assert nmap["available"] is False
    assert nmap["required_for_core"] is False
