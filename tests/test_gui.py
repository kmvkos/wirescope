from pathlib import Path

from tests.helpers import http_request
from tests.test_api import create_audit

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
SCREENS = (
    "login",
    "home",
    "environment",
    "interface",
    "scope",
    "profile",
    "confirm",
    "progress",
    "summary",
    "assets",
    "observations",
    "assessment",
    "findings",
    "report",
)


def test_frontend_defines_kiosk_workflow_screens():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    css = (FRONTEND / "style.css").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    for name in SCREENS:
        assert f'data-screen="{name}"' in html
    assert "min-height: 44px" in css
    assert "480px" in css
    assert "min-width: 900px" in css
    assert "wirescope.activeAudit" in script
    assert "beforeunload" not in script
    assert "pagehide" not in script
    assert "Viewer cannot start" in script or "viewer cannot start" in script.lower()
    assert 'role="alertdialog"' in html
    assert 'id="stop-audit-button"' in html


def test_root_is_public_and_static_assets_load(api_context):
    app, _service, _evidence, _environment = api_context

    page = http_request(app, "GET", "/", auth=False)
    css = http_request(app, "GET", "/static/style.css", auth=False)
    script = http_request(app, "GET", "/static/app.js", auth=False)

    assert page.status_code == 200
    assert css.status_code == 200
    assert script.status_code == 200
    assert "min-height: 44px" in css.text
    for name in SCREENS:
        assert f'data-screen="{name}"' in page.text


def test_auditor_workflow_creates_jobs_and_survives_ui_refresh(api_context):
    app, service, _evidence, _environment = api_context

    created = create_audit(app)
    assert created.status_code == 201
    assert created.json()["actor"] == "auditor"
    audit_id = created.json()["id"]

    queued = http_request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={"duration_seconds": 30},
    )
    assert queued.status_code == 202
    job_id = queued.json()["job_id"]

    refreshed = http_request(app, "GET", f"/api/audits/{audit_id}")
    jobs = http_request(app, "GET", f"/api/audits/{audit_id}/jobs")
    assert refreshed.status_code == 200
    assert jobs.json()["items"][0]["id"] == job_id
    assert jobs.json()["items"][0]["status"] == "queued"
    assert service.get_job(job_id).status.value == "queued"


def test_viewer_cannot_start_or_cancel_but_can_read(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    job_id = http_request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={},
    ).json()["job_id"]

    start = http_request(
        app,
        "POST",
        "/api/audits",
        as_role="viewer",
        json={"profile": "passive", "interface": "eth0", "scope": {}},
    )
    cancel = http_request(
        app,
        "POST",
        f"/api/jobs/{job_id}/cancel",
        as_role="viewer",
    )
    listing = http_request(
        app,
        "GET",
        f"/api/audits/{audit_id}/jobs",
        as_role="viewer",
    )

    assert start.status_code == 403
    assert cancel.status_code == 403
    assert listing.status_code == 200
    assert listing.json()["items"][0]["status"] == "queued"


def test_me_policy_exposes_duration_limits_for_the_gui(api_context):
    app, _service, _evidence, _environment = api_context
    me = http_request(app, "GET", "/api/auth/me")
    viewer = http_request(app, "GET", "/api/auth/me", as_role="viewer")

    assert me.json()["policy"]["passive_duration_default"] == 30
    assert "start_audits" in me.json()["capabilities"]
    assert viewer.json()["capabilities"] == []
    assert viewer.json()["role"] == "viewer"
