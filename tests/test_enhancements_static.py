from pathlib import Path


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def test_operator_insights_assets_are_loaded_by_root_page():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")

    assert '<link rel="stylesheet" href="/static/enhancements.css">' in html
    assert '<script src="/static/enhancements.js"></script>' in html


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
