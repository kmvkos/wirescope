from pathlib import Path

from tests.helpers import http_request as request


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_root_loads_product_coherence_assets(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/", auth=False)
    assert response.status_code == 200
    assert "/static/product_coherence.css?v=20260827-ui25" in response.text
    assert "/static/product_coherence.js?v=20260827-ui25" in response.text
    assert "/static/topology_tab.js?v=20260825-ui14&feature=20260826-ui17&coherence=20260827-ui25" in response.text


def test_topology_navigation_treats_management_sources_as_optional():
    script = _text("frontend/topology_tab.js")
    assert 'topologyButton.textContent = "Топология"' in script
    assert 'compareButton.textContent = "История топологии"' in script
    assert 'extrasButton.textContent = "Дополнительно"' in script
    assert 'snmpButton.textContent = "SNMP enrichment"' in script
    assert 'sshButton.textContent = "SSH enrichment"' in script
    assert "ws-extra-snmp-open" in script
    assert "ws-extra-ssh-open" in script
    assert "ensureExtraModule" in script
    assert 'snmp: "/static/snmp_topology.js?v=20260825-ui14&feature=20260825-ui16"' in script
    assert 'ssh: "/static/ssh_topology.js?v=20260826-ui18"' in script
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
    assert '["Слабые места", "Проблемы"]' in script
    assert "порт доступа коммутатора" in script
    assert '["L3-адрес на NIC захвата", "L3-адрес на интерфейсе захвата"]' in script


def test_correlated_assessment_machine_warnings_are_localized_only_in_presentation():
    script = _text("frontend/product_coherence.js")
    builder = _text("global_analysis/builder.py")

    warning = "Selected traffic analysis does not contain a usable communications graph."
    assert warning in builder
    assert warning in script
    assert "Выбранный анализ PCAP не содержит пригодного графа коммуникаций" in script
    assert "Список устройств превышает лимит входных данных" in script
    assert '[" · Traffic ", " · PCAP "]' in script
    assert '["CA ", "Корреляция "]' in script
    assert '[" · deep ·", " · Глубокий ·"]' in script
    assert '["Evidence lineage", "Источники и ссылки на доказательства"]' in script
    assert '["трафик сервиса наблюдался", "трафик службы наблюдался"]' in script


def test_human_report_cleanup_does_not_change_canonical_json_contract():
    router = _text("backend/routers/reports.py")
    cleanup = _text("reports/presentation_cleanup.py")
    assert 'if requested == "json":' in router
    assert "polish_human_report(render_markdown(document))" in router
    assert "polish_human_report(render_html(localized_report(canonical)))" in router
    assert '("Все findings", "Все проблемы")' in cleanup
    assert '("Evidence-артефакты", "Артефакты доказательств")' in cleanup
    assert "Asset list exceeded the report input limit" in cleanup
    assert "Список устройств превышает лимит данных отчёта" in cleanup
