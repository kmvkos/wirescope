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
    assert page.text.count('/static/progress_runtime.js') == 1
    assert page.text.count('/static/report_management.js') == 1
    assert page.text.count('/static/report_management.css') == 1
    assert page.text.count('/static/audit_management.js') == 1
    assert page.text.count('/static/audit_management.css') == 1
    assert page.text.count('/static/traffic_analysis.js') == 1
    assert page.text.count('/static/traffic_analysis.css') == 1
    assert page.text.count('/static/topology.js') == 1
    assert page.text.count('/static/topology_tab.js') == 1
    assert page.text.count('/static/topology.css') == 1
    assert page.text.count('/static/operations.js') == 1
    assert page.text.count('/static/modern.css') == 1
    assert page.text.count('/static/polish.css') == 1
    assert "?v=20260825-ui11" in page.text
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


def test_polish_layer_is_presentation_only_and_responsive():
    polish = (FRONTEND / "polish.css").read_text(encoding="utf-8")

    assert "h1::before" in polish
    assert "#new-audit-button::before" in polish
    assert "#audit-list" in polish
    assert "grid-template-columns: repeat(2" in polish
    assert "@media (max-width: 560px)" in polish
    assert "@media (min-width: 900px)" in polish
    assert "@media (prefers-reduced-motion: reduce)" in polish
    assert "ws-screen-in" in polish
    assert "url(" not in polish  # no remote fonts/images in the appliance UI


def test_long_nmap_stage_shows_live_results_without_fake_overall_percent():
    runtime = (FRONTEND / "progress_runtime.js").read_text(encoding="utf-8")
    insights = (FRONTEND / "enhancements.js").read_text(encoding="utf-8")

    assert '"discovering_hosts"' in runtime
    assert '"scanning_tcp"' in runtime
    assert '"fingerprinting_services"' in runtime
    assert '"udp_discovery"' in runtime
    assert 'label.textContent = "…"' in runtime
    assert 'meta.textContent = "идёт"' in runtime
    assert 'progress-live-result' in runtime
    assert 'raw.startsWith("Nmap live")' in runtime
    assert 'Nmap проверяет TCP-порты найденных хостов' in runtime
    assert 'только на найденных открытых TCP-портах' in runtime
    assert 'discovery: "Поиск устройств"' in insights
    assert 'findings: "Выводы"' in insights
    assert 'externalNmapStage(item)' in insights
    assert '? "идёт"' in insights


def test_report_management_is_auditor_only_and_keeps_audit_data():
    script = (FRONTEND / "report_management.js").read_text(encoding="utf-8")
    css = (FRONTEND / "report_management.css").read_text(encoding="utf-8")

    assert 'const API = "/api/v1"' in script
    assert 'me.role === "auditor"' in script
    assert 'request(\n                                "DELETE"' in script
    assert '"История отчётов"' in script
    assert '"Удалить"' in script
    assert 'Сам аудит, найденные устройства, сервисы, findings и evidence останутся.' in script
    assert 'format=markdown' not in script  # format is composed through exportUrl
    assert 'exportUrl(auditId, report.id, "markdown")' in script
    assert ".report-history-item" in css
    assert "@media (max-width: 560px)" in css


def test_traffic_analysis_ui_is_capture_scoped_and_kiosk_responsive():
    script = (FRONTEND / "traffic_analysis.js").read_text(encoding="utf-8")
    css = (FRONTEND / "traffic_analysis.css").read_text(encoding="utf-8")

    assert 'const API = "/api/v1"' in script
    assert '`/captures/${encodeURIComponent(captureJobId)}/analyze`' in script
    assert 'exportUrl(jobId, "text")' in script
    assert 'exportUrl(jobId, "markdown")' in script
    assert 'exportUrl(jobId, "json")' in script
    assert 'button.dataset.captureJobId' in script
    assert 'button.onclick =' not in script
    assert '"Анализировать"' in script
    assert ".traffic-analysis-modal" in css
    assert "@media (max-width: 560px)" in css


def test_topology_ui_has_global_segments_layers_and_explicit_overlay():
    script = (FRONTEND / "topology.js").read_text(encoding="utf-8")
    tab = (FRONTEND / "topology_tab.js").read_text(encoding="utf-8")
    css = (FRONTEND / "topology.css").read_text(encoding="utf-8")

    assert 'const API = "/api/v1"' in script
    assert '"Без PCAP overlay"' in script
    assert 'traffic_analysis_job_id=' in script
    assert '"Общая карта всех сохранённых сетей"' in script
    assert '"Все подсети текущего аудита"' in script
    assert '"L2 — канальный"' in script
    assert '"L3 — маршрутизация"' in script
    assert '"Traffic — PCAP"' in script
    assert 'request("/topology/global?limit=100")' in script
    assert '"Топология"' in tab
    assert 'window.WireScopeTopology.render' in tab
    assert '.ws-topology-confirmed' in css
    assert '.ws-topology-observed' in css
    assert '.ws-topology-inferred' in css
    assert '.ws-topology-segment-card' in css
    assert "@media (max-width: 560px)" in css


def test_upgrade_refreshes_enabled_kiosk_after_frontend_update():
    root = FRONTEND.parent
    script = (root / "packaging" / "upgrade.sh").read_text(encoding="utf-8")

    assert "systemctl is-enabled --quiet wirescope-kiosk.service" in script
    assert "systemctl reset-failed wirescope-kiosk.service" in script
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
