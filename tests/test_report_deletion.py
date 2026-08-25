import pytest

from jobs.models import RetentionClass
from jobs.service import EntityNotFound
from reports.store import ReportNotFound
from tests.helpers import http_request


def _seed_report(app, job_service, evidence_store):
    audit = job_service.create_audit(
        profile="standard",
        interface="eth0",
        scope={"targets": ["192.0.2.10/32"]},
        actor="auditor",
    )
    json_artifact = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_json",
        document={"schema": "audit-report", "schema_version": 1},
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report",
        schema_version=1,
    )
    html_artifact = evidence_store.put_bytes(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_html",
        payload=b"<html><body>report</body></html>",
        content_type="text/html; charset=utf-8",
        extension=".html",
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report-html",
        schema_version=1,
    )
    report = app.state.reports.create(
        audit_id=audit.id,
        job_id=None,
        actor="auditor",
        source_hash="a" * 64,
        summary={"summary": "fixture"},
        json_artifact_id=json_artifact.id,
        html_artifact_id=html_artifact.id,
    )
    return audit, report, json_artifact, html_artifact


def test_viewer_cannot_delete_generated_report(api_context):
    app, job_service, evidence_store, _environment = api_context
    audit, report, _json_artifact, _html_artifact = _seed_report(
        app, job_service, evidence_store
    )

    response = http_request(
        app,
        "DELETE",
        f"/api/v1/audits/{audit.id}/reports/{report.id}",
        as_role="viewer",
    )

    assert response.status_code == 403
    assert app.state.reports.get(audit.id, report.id).id == report.id


def test_auditor_deletes_report_but_keeps_audit(api_context):
    app, job_service, evidence_store, _environment = api_context
    audit, report, json_artifact, html_artifact = _seed_report(
        app, job_service, evidence_store
    )
    json_path = evidence_store.path_for(json_artifact)
    html_path = evidence_store.path_for(html_artifact)
    assert json_path.is_file()
    assert html_path.is_file()

    response = http_request(
        app,
        "DELETE",
        f"/api/v1/audits/{audit.id}/reports/{report.id}",
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["deleted"] is True
    assert payload["report_id"] == report.id
    assert set(payload["deleted_artifact_ids"]) == {
        json_artifact.id,
        html_artifact.id,
    }
    assert payload["file_cleanup_pending"] == []

    with pytest.raises(ReportNotFound):
        app.state.reports.get(audit.id, report.id)
    with pytest.raises(EntityNotFound):
        job_service.artifact(json_artifact.id)
    with pytest.raises(EntityNotFound):
        job_service.artifact(html_artifact.id)

    assert not json_path.exists()
    assert not html_path.exists()
    assert job_service.get_audit(audit.id).id == audit.id

    page = http_request(app, "GET", f"/api/v1/audits/{audit.id}/reports")
    assert page.status_code == 200
    assert page.json()["total"] == 0

    events = app.state.audit_log.list_events(action="report.delete", audit_id=audit.id)
    assert events["total"] >= 1
    assert events["items"][0]["status_code"] == 200
