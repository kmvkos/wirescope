from pathlib import Path

from tests.helpers import http_request


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def test_operator_insights_assets_are_loaded_by_root_page(api_context):
    app, _service, _evidence, _environment = api_context
    source = (FRONTEND / "index.html").read_text(encoding="utf-8")
    page = http_request(app, "GET", "/", auth=False)

    assert '<link rel="stylesheet" href="/static/enhancements.css">' in source
    assert '<script src="/static/enhancements.js"></script>' in source
    assert source.count('/static/enhancements.js') == 1
    assert page.status_code == 200
    assert page.text.count('/static/enhancements.js') == 1
    assert page.text.count('/static/operations.js') == 1
    assert page.text.count('/static/modern.css') == 1
    assert "?v=20260825-ui2" in page.text
    assert page.headers["cache-control"] == "no-store, max-age=0"


def test_modern_theme_keeps_kiosk_and_desktop_breakpoints():
    theme = (FRONTEND / "modern.css").read_text(encoding="utf-8")

    assert "--ws-primary" in theme
    assert "@media (max-width: 560px)" in theme
    assert "@media (min-width: 900px)" in theme
    assert "#screen-login form" in theme
    assert "#screen-home > .actions" in theme
    assert ".progress-hud" in theme
    assert ".ws-insights" in theme


def test_upgrade_refreshes_running_kiosk_after_frontend_update():
    root = FRONTEND.parent
    script = (root / "packaging" / "upgrade.sh").read_text(encoding="utf-8")

    assert "systemctl is-active --quiet wirescope-kiosk.service" in script
    assert "systemctl restart wirescope-kiosk.service" in script


def test_operator_insights_use_versioned_api_and_audit_scoped_evidence():
    script = (FRONTEND / "enhancements.js").read_text(encoding="utf-8")

    assert 'const API = "/api/v1"' in script
    assert "item.url" in script
    assert "/audits/${auditId}/artifacts/" in script
    assert "${API}/artifacts/" not in script
    assert 'request("/capabilities")' in script
    assert "caps.web" in script
    assert "all_interfaces" in script


def test_operator_insights_integrate_markdown_export_and_session_visibility():
    script = (FRONTEND / "enhancements.js").read_text(encoding="utf-8")

    assert 'id = "download-markdown-report"' in script
    assert "export?format=markdown" in script
    assert 'document.getElementById("session-chip")' in script
    assert 'attributeFilter: ["hidden"]' in script


def test_lifecycle_panel_is_versioned_preview_first_and_scoped_to_auditor():
    script = (FRONTEND / "operations.js").read_text(encoding="utf-8")

    assert 'const API = "/api/v1"' in script
    assert 'me.role !== "auditor"' in script
    assert 'confirm: false, include_raw: true' in script
    assert 'confirm: true, include_raw: true' in script
    assert 'window.confirm(' in script
    assert '/diagnostics' in script
    assert '/audit-log' not in script  # diagnostics already carries recent log entries
    assert '/jobs/${encodeURIComponent(job.id)}/retry' in script
