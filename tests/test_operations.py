from datetime import timedelta

import pytest

from jobs.models import ErrorCategory, JobError, RetentionClass
from jobs.service import EntityNotFound
from persistence.models import ArtifactModel, utc_now
from tests.helpers import http_request as request


def _audit(service, *, profile="standard"):
    return service.create_audit(
        profile=profile,
        interface="eth0",
        scope={"targets": ["192.0.2.0/24"], "confirmed": True},
        actor="auditor",
    )


def test_operational_log_records_authentication_and_mutation(api_context):
    app, _service, _evidence, _environment = api_context

    failed = request(
        app,
        "POST",
        "/api/v1/auth/login",
        auth=False,
        json={"username": "auditor", "password": "wrong-password"},
    )
    assert failed.status_code == 401

    created = request(
        app,
        "POST",
        "/api/v1/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {},
        },
    )
    assert created.status_code == 201

    log = request(app, "GET", "/api/v1/audit-log?limit=100")
    assert log.status_code == 200
    items = log.json()["items"]
    assert any(
        item["action"] == "auth.login"
        and item["actor"] == "auditor"
        and item["status_code"] == 401
        for item in items
    )
    assert any(
        item["action"] == "audit.create"
        and item["actor"] == "auditor"
        and item["status_code"] == 201
        and item["audit_id"] is None
        for item in items
    )
    serialized = str(items).lower()
    assert "wrong-password" not in serialized
    assert "auditor-pass" not in serialized


def test_operational_log_is_auditor_only(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(
        app,
        "GET",
        "/api/v1/audit-log",
        as_role="viewer",
    )
    assert response.status_code == 403


def test_failed_job_can_be_retried_as_new_durable_job(api_context):
    app, service, _evidence, _environment = api_context
    audit = _audit(service)
    original = service.create_job(
        audit_id=audit.id,
        job_type="protocol_audit",
        target="eth0",
        parameters={"selected_modules": ["ssh"]},
        resource_key=f"audit:{audit.id}",
        resource_group="protocol",
        resource_limit=1,
    )
    claimed = service.claim_next("test-retry-worker")
    assert claimed is not None and claimed.id == original.id
    service.fail_job(
        original.id,
        JobError(
            code="provider_temporarily_unavailable",
            category=ErrorCategory.INTERNAL,
            message="temporary test failure",
            component="test",
            retryable=True,
        ),
    )

    retried = request(app, "POST", f"/api/v1/jobs/{original.id}/retry")
    assert retried.status_code == 202, retried.text
    payload = retried.json()
    assert payload["retry_of"] == original.id
    assert payload["job_id"] != original.id
    assert payload["status"] == "queued"
    assert payload["status_url"].startswith("/api/v1/jobs/")

    replacement = service.get_job(payload["job_id"])
    assert replacement.parameters == original.parameters
    assert replacement.type == original.type
    assert replacement.target == original.target
    assert service.get_audit(audit.id).status.value == "running"

    duplicate = request(app, "POST", f"/api/v1/jobs/{original.id}/retry")
    assert duplicate.status_code == 409


def test_raw_cleanup_is_preview_first_and_requires_confirmation(api_context):
    app, service, evidence, _environment = api_context
    audit = _audit(service, profile="packet_capture")
    artifact = evidence.put_bytes(
        audit_id=audit.id,
        job_id=None,
        artifact_type="packet_capture",
        payload=b"pcap-test-payload",
        content_type="application/vnd.tcpdump.pcap",
        extension=".pcap",
        retention_class=RetentionClass.AUDIT,
    )
    path = evidence.path_for(artifact)
    assert path.is_file()

    with service.database.session() as session, session.begin():
        model = session.get(ArtifactModel, artifact.id)
        assert model is not None
        model.created_at = utc_now() - timedelta(days=31)

    preview = request(
        app,
        "POST",
        "/api/v1/maintenance/cleanup",
        json={"confirm": False, "include_raw": True},
    )
    assert preview.status_code == 200
    assert preview.json()["would_delete"]["count"] >= 1
    assert path.is_file()
    assert service.artifact(artifact.id).id == artifact.id

    applied = request(
        app,
        "POST",
        "/api/v1/maintenance/cleanup",
        json={"confirm": True, "include_raw": True},
    )
    assert applied.status_code == 200
    assert applied.json()["deleted"]["artifact_rows"] >= 1
    assert not path.exists()
    with pytest.raises(EntityNotFound):
        service.artifact(artifact.id)


def test_diagnostics_exposes_runtime_and_storage_health(api_context):
    app, service, _evidence, _environment = api_context
    service.register_worker("diagnostics-worker")
    service.heartbeat_worker("diagnostics-worker", status="idle")

    response = request(app, "GET", "/api/v1/diagnostics")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema"] == "wirescope-diagnostics"
    assert payload["runtime"]["checks"]["database"] is True
    assert payload["runtime"]["checks"]["migrations"] is True
    assert payload["runtime"]["checks"]["database_quick_check"] is True
    assert payload["lifecycle"]["retention"]["automatic_raw_deletion"] is False
    assert payload["listener"]["bind_host"] == "0.0.0.0"

    exported = request(app, "GET", "/api/v1/diagnostics/export")
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    assert b"wirescope-diagnostics" in exported.content
