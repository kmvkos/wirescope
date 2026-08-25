from pathlib import Path

from jobs.models import RetentionClass
from tests.helpers import http_request as request


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def create_audit(app):
    response = request(
        app,
        "POST",
        "/api/v1/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"site": "delete-test"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_full_audit_delete_is_auditor_only_and_removes_evidence(api_context):
    app, service, evidence, _environment = api_context
    audit_id = create_audit(app)

    extra = evidence.put_bytes(
        audit_id=audit_id,
        job_id=None,
        artifact_type="delete_test",
        payload=b"audit-owned-evidence",
        content_type="application/octet-stream",
        extension=".bin",
        retention_class=RetentionClass.AUDIT,
    )
    evidence_path = evidence.path_for(extra)
    assert evidence_path.exists()
    assert (evidence.root / audit_id).exists()

    viewer = request(
        app,
        "DELETE",
        f"/api/v1/audits/{audit_id}",
        as_role="viewer",
    )
    assert viewer.status_code == 403
    assert service.get_audit(audit_id).id == audit_id
    assert evidence_path.exists()

    deleted = request(app, "DELETE", f"/api/v1/audits/{audit_id}")
    assert deleted.status_code == 200, deleted.text
    payload = deleted.json()
    assert payload["deleted"] is True
    assert payload["audit_id"] == audit_id
    assert payload["artifact_count"] >= 2  # environment snapshot + test artifact
    assert payload["file_cleanup_pending"] is False
    assert not (evidence.root / audit_id).exists()

    missing = request(app, "GET", f"/api/v1/audits/{audit_id}")
    assert missing.status_code == 404
    listed = request(app, "GET", "/api/v1/audits?limit=100")
    assert audit_id not in {item["id"] for item in listed.json()["items"]}

    events = app.state.audit_log.list_events(action="audit.delete", audit_id=audit_id)
    assert events["total"] == 2
    assert {item["status_code"] for item in events["items"]} == {200, 403}


def test_running_or_queued_audit_must_be_stopped_before_delete(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app)

    accepted = request(
        app,
        "POST",
        f"/api/v1/audits/{audit_id}/passive",
        json={"duration_seconds": 30},
    )
    assert accepted.status_code == 202
    job_id = accepted.json()["job_id"]

    blocked = request(app, "DELETE", f"/api/v1/audits/{audit_id}")
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "audit_busy"
    assert service.get_audit(audit_id).id == audit_id

    stopped = request(app, "POST", f"/api/v1/jobs/{job_id}/cancel")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "cancelled"

    deleted = request(app, "DELETE", f"/api/v1/audits/{audit_id}")
    assert deleted.status_code == 200, deleted.text
    assert request(app, "GET", f"/api/v1/audits/{audit_id}").status_code == 404


def test_audit_delete_controls_are_loaded_for_web_and_kiosk(api_context):
    app, _service, _evidence, _environment = api_context
    page = request(app, "GET", "/", auth=False)
    script = (FRONTEND / "audit_management.js").read_text(encoding="utf-8")
    css = (FRONTEND / "audit_management.css").read_text(encoding="utf-8")

    assert page.status_code == 200
    assert page.text.count("/static/audit_management.js") == 1
    assert page.text.count("/static/audit_management.css") == 1
    assert 'const API = "/api/v1"' in script
    assert 'me && me.role === "auditor"' in script
    assert '"DELETE"' in script
    assert '"Удалить аудит?"' in script
    assert '"audit_busy"' in script
    assert ".audit-manage-row" in css
    assert "@media (max-width: 560px)" in css
