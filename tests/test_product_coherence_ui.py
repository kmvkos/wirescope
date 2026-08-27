from pathlib import Path

from tests.helpers import http_request as request


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_root_loads_product_coherence_assets(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/", auth=False)
    assert response.status_code == 200
    assert "/static/product_coherence.css?v=20260827-ui20" in response.text
    assert "/static/product_coherence.js?v=20260827-ui20" in response.text
    assert "/static/topology_tab.js?v=20260825-ui14&feature=20260826-ui17&coherence=20260827-ui20" in response.text


def test_topology_navigation_treats_management_sources_as_optional():
    script = _text("frontend/topology_tab.js")
    assert 'topologyButton.textContent = "Топология"' in script
    assert 'compareButton.textContent = "История топологии"' in script
    assert 'extrasButton.textContent = "Дополнительно"' in script
    assert 'snmpButton.textContent = "SNMP enrichment"' in script
    assert 'sshButton.textContent = "SSH enrichment"' in script
    assert "ws-extra-snmp-open" in script
    assert "ws-extra-ssh-open" in script
    assert "История topology" not in script


def test_management_panels_are_hidden_until_explicitly_opened():
    css = _text("frontend/product_coherence.css")
    assert "#ws-insights-body:not(.ws-extra-snmp-open) .ws-snmp-topology-panel" in css
    assert "#ws-insights-body:not(.ws-extra-ssh-open) .ws-ssh-topology-panel" in css
    assert "grid-template-columns: 1fr !important" in css
    assert "overflow-wrap: anywhere" in css


def test_operator_terminology_cleanup_is_loaded_for_legacy_saved_results():
    script = _text("frontend/product_coherence.js")
    assert '["SNMP enrichment", "SNMP-опрос"]' in script
    assert '["SSH enrichment", "SSH-сбор данных"]' in script
    assert '"inventory assets", "устройств инвентаря"' in script
    assert '"source_health, coverage и warnings"' in script


def test_human_report_cleanup_does_not_change_canonical_json_contract():
    router = _text("backend/routers/reports.py")
    cleanup = _text("reports/presentation_cleanup.py")
    assert 'if requested == "json":' in router
    assert "polish_human_report(render_markdown(document))" in router
    assert "polish_human_report(render_html(localized_report(canonical)))" in router
    assert '("Все findings", "Все проблемы")' in cleanup
    assert '("Evidence-артефакты", "Артефакты доказательств")' in cleanup
