from tests.helpers import http_request


def test_root_loads_milestone_12_topology_evidence_assets_after_topology_wrappers(api_context):
    app, _service, _evidence, _environment = api_context

    page = http_request(app, "GET", "/", auth=False)
    script = http_request(
        app,
        "GET",
        "/static/topology_evidence_ui.js",
        auth=False,
    )
    css = http_request(
        app,
        "GET",
        "/static/topology_evidence_ui.css",
        auth=False,
    )

    assert page.status_code == 200
    assert script.status_code == 200
    assert css.status_code == 200

    assert "/static/topology_evidence_ui.css?v=20260828-ui19" in page.text
    assert "/static/topology_evidence_ui.js?v=20260828-ui19" in page.text
    assert page.text.index("/static/ssh_topology.js") < page.text.index(
        "/static/topology_evidence_ui.js"
    )
    assert page.text.index("/static/topology_evidence_ui.js") < page.text.index(
        "/static/topology_tab.js"
    )

    assert 'version: "m12-evidence-ui"' in script.text
    assert "preferredView" in script.text
    assert "different_domain" in script.text
    assert "l3_next_hop" in script.text
    assert "ws-topology-pcap-evidence" in css.text
