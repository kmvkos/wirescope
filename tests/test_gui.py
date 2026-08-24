from pathlib import Path
import re

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


def _locale_keys(script: str, locale: str) -> set[str]:
    marker = f"{locale}: {{"
    start = script.index(marker) + len(marker) - 1
    depth = 0
    end = start
    for index, char in enumerate(script[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    return set(re.findall(r'"([a-zA-Z0-9_.]+)":', script[start : end + 1]))


def test_frontend_defines_kiosk_workflow_screens():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    css = (FRONTEND / "style.css").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    i18n = (FRONTEND / "i18n.js").read_text(encoding="utf-8")

    for name in SCREENS:
        assert f'data-screen="{name}"' in html
    assert 'lang="ru"' in html
    assert "/static/i18n.js" in html
    assert "Сеть / VLAN / область" in html
    assert "уполномоченный диапазон" in html or "уполномоченный L3-диапазон" in html
    assert 'id="scope-proposal"' in html
    assert 'data-i18n="scope.confirmAction"' in html
    assert "<details class=\"advanced\">" in html
    assert 'id="scope-targets"' in html
    assert "Будем сканировать эти сети" in i18n
    assert "один CIDR или хост на строку" in i18n
    assert 'data-profile="passive"' in html
    assert 'data-profile="discovery"' in html
    assert 'data-profile="standard"' in html
    assert 'data-profile="deep"' in html
    assert "min-height: 44px" in css
    assert "480px" in css
    assert "min-width: 900px" in css
    assert "wirescope.activeAudit" in script
    assert "beforeunload" not in script
    assert "pagehide" not in script
    assert 't("error.viewerCannotStart")' in script
    assert "combinedTargets()" in script
    assert "derived_from" in script
    assert "applyVlanScanInterface" in script
    assert "/api/scope/proposal" in script
    assert "loadScopeProposal" in script
    assert "await showConfirm()" in script
    assert "state.draft.proposed" in script
    assert "job.dumpcapPermission" in i18n
    assert "службе не хватает группы wireshark" in i18n
    assert "Захват завершён без кадров" in i18n
    assert "Итоговая сводка" in i18n
    assert "VLAN в кадре виден только при 802.1Q" in i18n
    assert "id=\"summary-note\"" in html
    assert "id=\"summary-conclusion\"" in html
    assert "id=\"summary-vlan-note\"" in html
    assert "required" not in html.split('id="scope-targets"')[1].split("</textarea>")[0]
    assert "Наблюдатель не может запускать аудиты" in i18n
    assert 'const locale = "ru"' in i18n
    assert 'role="alertdialog"' in html
    assert 'id="stop-audit-button"' in html


def test_i18n_russian_default_matches_english_fallback_keys():
    i18n = (FRONTEND / "i18n.js").read_text(encoding="utf-8")
    russian = _locale_keys(i18n, "ru")
    english = _locale_keys(i18n, "en")
    assert russian == english
    assert "login.title" in russian
    assert "scope.hint" in russian
    assert "error.invalid_credentials" in russian


def test_root_is_public_and_static_assets_load(api_context):
    app, _service, _evidence, _environment = api_context

    page = http_request(app, "GET", "/", auth=False)
    css = http_request(app, "GET", "/static/style.css", auth=False)
    script = http_request(app, "GET", "/static/app.js", auth=False)
    i18n = http_request(app, "GET", "/static/i18n.js", auth=False)

    assert page.status_code == 200
    assert css.status_code == 200
    assert script.status_code == 200
    assert i18n.status_code == 200
    assert "min-height: 44px" in css.text
    assert 'lang="ru"' in page.text
    assert "Войти" in page.text
    assert "const locale = \"ru\"" in i18n.text
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


def test_scope_proposal_endpoint_derives_interface_prefix(api_context):
    app, _service, _evidence, _environment = api_context

    response = http_request(
        app,
        "GET",
        "/api/scope/proposal",
        params={"interface": "eth0"},
    )
    missing = http_request(
        app,
        "GET",
        "/api/scope/proposal",
        params={"interface": "eth9"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "interface_prefix"
    assert payload["canonical_targets"] == ["192.0.2.0/24"]
    assert payload["assigned_addresses"] == ["192.0.2.10/24"]
    assert "0.0.0.0/0" not in payload["canonical_targets"]
    assert "::/0" not in payload["canonical_targets"]
    assert missing.status_code == 422
    assert missing.json()["detail"]["code"] == "unknown_interface"
