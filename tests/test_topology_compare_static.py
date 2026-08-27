from tests.helpers import http_request as request


def test_topology_history_assets_are_versioned_and_ordered(api_context):
    app, _service, _evidence, _environment = api_context
    root = request(app, "GET", "/", as_role=None)
    assert root.status_code == 200
    body = root.text

    assert body.count("topology_compare.css?v=20260825-ui15") == 1
    assert body.count("topology_compare.js?v=20260825-ui15") == 1
    assert body.count("topology_tab.js?v=20260825-ui14&feature=20260826-ui17") == 1
    assert "&coherence=20260827-ui20" in body
    assert body.index("topology.js?v=20260825-ui14") < body.index("topology_compare.js?v=20260825-ui15")
    assert body.index("topology_compare.js?v=20260825-ui15") < body.index("topology_tab.js?v=20260825-ui14")


def test_topology_history_frontend_uses_versioned_read_only_compare_api(api_context):
    app, _service, _evidence, _environment = api_context
    javascript = request(app, "GET", "/static/topology_compare.js", as_role=None)
    tab = request(app, "GET", "/static/topology_tab.js", as_role=None)
    css = request(app, "GET", "/static/topology_compare.css", as_role=None)

    assert javascript.status_code == 200
    assert 'const API = "/api/v1"' in javascript.text
    assert '/topology/global?limit=100' in javascript.text
    assert '/topology/compare?against=' in javascript.text
    assert "не запускает сканирование, SNMP или traceroute" in javascript.text
    assert "hostname сам по себе — нет" in javascript.text
    assert "Скачать diff JSON" in javascript.text

    assert tab.status_code == 200
    assert "История топологии" in tab.text
    assert "Дополнительно" in tab.text
    assert "WireScopeTopologyCompare.render" in tab.text

    assert css.status_code == 200
    assert "@media (max-width: 560px)" in css.text
