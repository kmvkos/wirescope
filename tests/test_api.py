from jobs.models import RetentionClass
from tests.helpers import http_request as request


def create_audit(app):
    return request(
        app,
        "POST",
        "/api/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"site": "lab"},
        },
    )


def test_health_and_environment_endpoints(api_context):
    app, _service, _evidence, environment = api_context

    health = request(app, "GET", "/api/health")
    status = request(app, "GET", "/api/status")
    response = request(app, "GET", "/api/environment")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert status.json() == health.json()
    assert response.json() == environment


def test_create_audit_persists_environment_reference(api_context):
    app, service, _evidence, _environment = api_context

    response = create_audit(app)

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "created"
    assert payload["environment_snapshot_reference"]
    assert service.get_audit(payload["id"]).scope == {"site": "lab"}


def test_enqueue_passive_job_and_paginated_listing(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={"duration_seconds": 45, "priority": 5},
    )

    assert response.status_code == 202
    job_id = response.json()["job_id"]
    persisted = service.get_job(job_id)
    assert persisted.parameters["duration_seconds"] == 45
    assert persisted.resource_key == "interface:eth0"
    listing = request(
        app,
        "GET",
        "/api/jobs",
        params={"limit": 1, "offset": 0, "status": "queued"},
    )
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["result_available"] is False
    audit_jobs = request(app, "GET", f"/api/audits/{audit_id}/jobs")
    assert audit_jobs.json()["items"][0]["id"] == job_id


def test_passive_job_rejects_out_of_range_duration(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={"duration_seconds": 999},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_duration"


def test_create_audit_rejects_unknown_interface(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(
        app,
        "POST",
        "/api/audits",
        json={"profile": "passive", "interface": "missing0"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_interface"


def test_create_audit_rejects_oversized_scope(api_context):
    app, _service, _evidence, _environment = api_context

    response = request(
        app,
        "POST",
        "/api/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"note": "x" * 20_000},
        },
    )

    assert response.status_code == 422


def test_queued_job_cancellation_endpoint(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    job_id = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={},
    ).json()["job_id"]

    response = request(app, "POST", f"/api/jobs/{job_id}/cancel")

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    events = request(app, "GET", f"/api/jobs/{job_id}/events")
    assert events.json()["total"] == 2


def test_separate_job_result_endpoint(api_context):
    app, service, evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    job_id = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={},
    ).json()["job_id"]
    service.claim_next("api-test-worker")
    document = {
        "schema": "passive-result",
        "schema_version": 1,
        "result": {"interface": "eth0"},
    }
    artifact = evidence.put_json(
        audit_id=audit_id,
        job_id=job_id,
        artifact_type="passive_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="passive-result",
        schema_version=1,
    )
    service.complete_job(job_id, result_reference=artifact.id)

    status = request(app, "GET", f"/api/jobs/{job_id}")
    result = request(app, "GET", f"/api/jobs/{job_id}/result")

    assert "result" not in status.json()
    assert status.json()["result_available"] is True
    assert result.json() == document


def test_readiness_distinguishes_missing_and_live_worker(api_context):
    app, service, _evidence, _environment = api_context

    unavailable = request(app, "GET", "/api/ready")
    service.register_worker("ready-worker")
    service.heartbeat_worker("ready-worker", status="idle")
    available = request(app, "GET", "/api/ready")

    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["worker"] is False
    assert available.status_code == 200
    assert available.json()["status"] == "ready"


def test_interfaces_missing_entities_and_removed_legacy_routes(api_context):
    app, _service, _evidence, _environment = api_context

    interfaces = request(app, "GET", "/api/interfaces")
    missing = request(app, "GET", "/api/jobs/missing")
    legacy = request(app, "POST", "/api/passive/start", json={})

    assert interfaces.json()["interfaces"][0]["name"] == "eth0"
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "not_found"
    assert legacy.status_code == 404


def test_root_serves_frontend(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/")

    assert response.status_code == 200
    assert "data-screen=\"login\"" in response.text
    assert "data-screen=\"progress\"" in response.text
    assert "WireScope" in response.text


def test_enqueue_discovery_confirms_scope_and_lists_empty_inventory(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={
            "interface": "eth0",
            "scope": ["192.0.2.0/24"],
            "profile": "standard",
        },
    )

    assert response.status_code == 202
    job = service.get_job(response.json()["job_id"])
    assert job.type == "active_discovery"
    assert job.parameters["scope"] == ["192.0.2.0/24"]
    assert job.parameters["confirmed_scope_id"]
    assert job.resource_key == "interface:eth0"
    assert job.resource_group == "active_discovery"
    status = request(app, "GET", f"/api/jobs/{job.id}")
    assert "assets" not in status.json()
    assets = request(app, "GET", f"/api/audits/{audit_id}/assets")
    services = request(
        app,
        "GET",
        f"/api/audits/{audit_id}/services",
        params={"port": 443},
    )
    summary = request(app, "GET", f"/api/audits/{audit_id}/inventory")
    assert assets.status_code == 200
    assert assets.json()["total"] == 0
    assert services.json()["total"] == 0
    assert summary.json()["assets"] == 0


def test_discovery_rejects_unspecified_and_oversize_scope(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    unspecified = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["0.0.0.0/0"], "profile": "discovery"},
    )
    ipv6 = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["::/0"], "profile": "standard"},
    )
    oversized = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["10.0.0.0/8"], "profile": "standard"},
    )
    assert unspecified.status_code == 422
    assert unspecified.json()["detail"]["code"] == "prohibited_target"
    assert ipv6.json()["detail"]["code"] == "prohibited_target"
    assert oversized.json()["detail"]["code"] == "scope_limit_exceeded"


def test_protocol_audit_requires_scope_and_inventory(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    missing_scope = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/protocol-audits",
        json={},
    )
    assert missing_scope.status_code == 422
    assert missing_scope.json()["detail"]["code"] == "scope_not_confirmed"

    request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={
            "interface": "eth0",
            "scope": ["192.0.2.0/24"],
            "profile": "standard",
        },
    )
    missing_services = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/protocol-audits",
        json={"modules": ["ssh"]},
    )
    assert missing_services.status_code == 422
    assert missing_services.json()["detail"]["code"] == "inventory_empty"

    from parsers.nmap import parse_nmap_xml
    from tests.fixtures.nmap import fixture_path

    app.state.inventory.ingest_nmap_document(
        audit_id=audit_id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    gated = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/protocol-audits",
        json={"modules": ["nuclei"]},
    )
    unknown = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/protocol-audits",
        json={"modules": ["ftp-brute"]},
    )
    extra_flags = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/protocol-audits",
        json={"modules": ["ssh"], "raw_flags": "-sC --script vuln"},
    )
    assert gated.status_code == 422
    assert gated.json()["detail"]["code"] == "module_gated"
    assert unknown.json()["detail"]["code"] == "unknown_module"
    assert extra_flags.status_code == 202
    job = service.get_job(extra_flags.json()["job_id"])
    assert job.type == "protocol_audit"
    assert job.parameters["modules"] == ["ssh"]
    assert "raw_flags" not in job.parameters
    assert job.resource_key == f"audit:{audit_id}"
    assert job.resource_group == "protocol_audit"
    listing = request(app, "GET", f"/api/audits/{audit_id}/observations")
    assert listing.status_code == 200
    assert listing.json()["total"] == 0
    assert listing.json()["items"] == []


def test_findings_api_lists_and_records_status_changes(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    empty = request(app, "GET", f"/api/audits/{audit_id}/findings")
    assert empty.status_code == 200
    assert empty.json()["total"] == 0

    from engine.passive_models import ConfidenceLevel
    from findings.models import FindingDraft, Severity
    from parsers.nmap import parse_nmap_xml
    from tests.fixtures.nmap import fixture_path

    app.state.inventory.ingest_nmap_document(
        audit_id=audit_id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    service_row = next(
        item
        for item in app.state.inventory.list_services(
            audit_id=audit_id,
            limit=10,
            offset=0,
        ).items
        if item.port == 22
    )
    created = app.state.findings.upsert_evaluation(
        audit_id=audit_id,
        drafts=[
            FindingDraft(
                rule_id="WS-SSH-WEAK-ALGORITHMS",
                rule_version="1",
                family="ssh",
                title="Weak SSH algorithms are offered",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                asset_id=service_row.asset_id,
                service_id=service_row.id,
                description="Weak algorithms were observed.",
                rationale="ssh_algorithms listed weak ciphers.",
                recommendation="Disable legacy algorithms.",
                data={"weak_algorithms": {"kex": ["diffie-hellman-group1-sha1"]}},
                observation_ids=["obs-1"],
                evidence_artifact_ids=["evidence-1"],
                dedupe_key=f"{service_row.asset_id}:{service_row.id}",
            )
        ],
    )
    listing = request(app, "GET", f"/api/audits/{audit_id}/findings")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    finding_id = created[0].id
    detail = request(app, "GET", f"/api/audits/{audit_id}/findings/{finding_id}")
    assert detail.status_code == 200
    assert detail.json()["rule_id"] == "WS-SSH-WEAK-ALGORITHMS"
    assert detail.json()["observation_ids"] == ["obs-1"]

    suppressed = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/findings/{finding_id}/suppress",
        json={"actor": "auditor", "reason": "Lab host"},
    )
    assert suppressed.status_code == 200
    assert suppressed.json()["status"] == "suppressed"
    assert suppressed.json()["state_events"][0]["actor"] == "auditor"

    accepted = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/findings/{finding_id}/accept-risk",
        json={"actor": "lead", "reason": "Compensating control"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted_risk"

    reopened = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/findings/{finding_id}/reopen",
        json={"actor": "lead", "reason": "Control removed"},
    )
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "open"

    queued = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/findings",
        json={"priority": 1},
    )
    assert queued.status_code == 202
    job = service.get_job(queued.json()["job_id"])
    assert job.type == "findings_evaluation"
    assert job.resource_key == f"audit:{audit_id}"
    assert job.resource_group == "findings"
    assert "raw_flags" not in job.parameters


def test_reports_api_enqueues_lists_and_rejects_pdf(api_context):
    app, service, evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    empty = request(app, "GET", f"/api/audits/{audit_id}/reports")
    assert empty.status_code == 200
    assert empty.json()["total"] == 0

    queued = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/reports",
        json={"actor": "auditor", "priority": 1, "output_path": "/etc/passwd"},
    )
    assert queued.status_code == 202
    job = service.get_job(queued.json()["job_id"])
    assert job.type == "report_generation"
    assert job.resource_key == f"audit:{audit_id}"
    assert job.resource_group == "report"
    assert job.parameters == {"actor": "auditor"}
    assert "output_path" not in job.parameters

    missing = request(
        app,
        "GET",
        f"/api/audits/{audit_id}/reports/00000000-0000-4000-8000-000000000099",
    )
    assert missing.status_code == 404
    pdf = request(
        app,
        "GET",
        f"/api/audits/{audit_id}/reports/"
        "00000000-0000-4000-8000-000000000099/export?format=pdf",
    )
    assert pdf.status_code == 422
    assert pdf.json()["detail"]["code"] == "pdf_not_available"
