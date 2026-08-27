from __future__ import annotations

import json
from pathlib import Path

import pytest


pytestmark = pytest.mark.browser
ROOT = Path(__file__).resolve().parents[1]


def _browser():
    playwright = pytest.importorskip("playwright.sync_api")
    instance = playwright.sync_playwright().start()
    try:
        browser = instance.chromium.launch(headless=True)
    except Exception as exc:
        instance.stop()
        pytest.skip(f"Chromium is unavailable: {exc}")
    return instance, browser


def _install_lazy_routes(page) -> dict[str, int]:
    calls = {"snmp_script": 0, "ssh_script": 0, "api": 0}

    def snmp_script(route):
        calls["snmp_script"] += 1
        route.fulfill(
            path=str(ROOT / "frontend/snmp_topology.js"),
            content_type="application/javascript; charset=utf-8",
        )

    def ssh_script(route):
        calls["ssh_script"] += 1
        route.fulfill(
            path=str(ROOT / "frontend/ssh_topology.js"),
            content_type="application/javascript; charset=utf-8",
        )

    def api(route):
        calls["api"] += 1
        url = route.request.url
        if url.endswith("/api/v1/auth/me"):
            payload = {"username": "auditor", "role": "auditor"}
        elif url.endswith("/api/v1/audits/audit-1/topology"):
            payload = {
                "schema": "network-topology",
                "schema_version": 1,
                "partial": False,
                "nodes": [],
                "edges": [],
                "segments": [],
                "snmp_topology": {},
                "ssh_topology": {},
            }
        else:
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

    page.route("http://wirescope.test/static/snmp_topology.js*", snmp_script)
    page.route("http://wirescope.test/static/ssh_topology.js*", ssh_script)
    page.route("http://wirescope.test/api/v1/**", api)
    return calls


def _load_workspace(page) -> dict[str, int]:
    calls = _install_lazy_routes(page)
    page.set_content(
        """
        <!doctype html><html lang="ru"><head><base href="http://wirescope.test/"></head><body>
        <div class="app"><main><section class="screen">
          <div id="legacy-findings-label">Слабые места</div>
          <div id="legacy-vlan-note">Тегов 802.1Q не видно. Access-порт часто без тега — ID неизвестен.</div>
          <div class="ws-insights-tabs"><button class="primary">Сводка</button></div>
          <select id="ws-audit-select"><option value="audit-1" selected>audit-1</option></select>
          <div id="ws-insights-body">
            <div class="card"><pre>very-long-technical-value-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</pre></div>
          </div>
        </section></main></div>

        <div id="traffic-analysis-modal" class="traffic-analysis-modal" hidden>
          <section class="traffic-analysis-card">
            <div class="traffic-analysis-head"><h2>Анализ сетевого трафика</h2><button>Закрыть</button></div>
            <div class="traffic-analysis-actions actions wrap"><button>TXT</button><button>Markdown</button><button>JSON</button></div>
            <pre class="traffic-analysis-report">very-long-traffic-value-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</pre>
          </section>
        </div>

        <div id="global-analysis-modal" class="global-analysis-modal" hidden>
          <section class="global-analysis-card">
            <header class="ga-head"><h2>Корреляция результатов</h2><button>Закрыть</button></header>
            <div class="ga-layout">
              <aside class="ga-sidebar"><select><option>very-long-selected-analysis-cccccccccccccccccccccccccccccccccccccccc</option></select></aside>
              <main class="ga-main"><div class="ga-content">very-long-correlation-value-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd</div></main>
            </div>
          </section>
        </div>

        <script>
          window.WireScopeTopology = { render: async () => {} };
          window.WireScopeTopologyCompare = { render: async () => {} };
        </script>
        </body></html>
        """
    )
    for stylesheet in (
        "frontend/style.css",
        "frontend/modern.css",
        "frontend/polish.css",
        "frontend/traffic_analysis.css",
        "frontend/global_analysis.css",
        "frontend/topology.css",
        "frontend/snmp_topology.css",
        "frontend/ssh_topology.css",
        "frontend/product_coherence.css",
    ):
        page.add_style_tag(path=str(ROOT / stylesheet))
    page.add_script_tag(path=str(ROOT / "frontend/topology_tab.js"))
    page.add_script_tag(path=str(ROOT / "frontend/product_coherence.js"))
    return calls


def _assert_no_page_overflow(page, width: int) -> None:
    sizes = page.evaluate(
        """() => ({
            body: document.body.scrollWidth,
            html: document.documentElement.scrollWidth,
            viewport: window.innerWidth,
        })"""
    )
    assert sizes["viewport"] == width
    assert sizes["body"] <= width
    assert sizes["html"] <= width


def _assert_element_inside_viewport(page, selector: str, width: int) -> None:
    box = page.locator(selector).bounding_box()
    assert box is not None
    assert box["x"] >= -1
    assert box["width"] <= width + 1
    assert box["x"] + box["width"] <= width + 1


@pytest.mark.parametrize("viewport", [(480, 320), (1280, 900)])
def test_topology_optional_sources_fit_kiosk_and_web(viewport):
    width, height = viewport
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": width, "height": height})
        calls = _load_workspace(page)

        assert page.locator("#legacy-findings-label").inner_text() == "Проблемы"
        assert "Порт доступа" in page.locator("#legacy-vlan-note").inner_text()
        assert page.get_by_role("button", name="Топология").count() == 1
        assert page.get_by_role("button", name="История топологии").count() == 1
        extras = page.get_by_role("button", name="Дополнительно")
        assert extras.count() == 1

        assert page.locator('script[data-ws-topology-extra]').count() == 0
        assert calls == {"snmp_script": 0, "ssh_script": 0, "api": 0}
        _assert_no_page_overflow(page, width)

        extras.click()
        assert page.get_by_role("button", name="SNMP-опрос").is_visible()
        assert page.get_by_role("button", name="SSH-сбор данных").is_visible()
        assert calls == {"snmp_script": 0, "ssh_script": 0, "api": 0}
        _assert_no_page_overflow(page, width)

        page.get_by_role("button", name="SNMP-опрос").click()
        page.locator(".ws-snmp-topology-panel").wait_for(state="visible")
        assert page.locator('script[data-ws-topology-extra="snmp"]').count() == 1
        assert calls["snmp_script"] == 1
        assert calls["api"] >= 2
        assert not page.locator(".ws-ssh-topology-panel").is_visible()
        assert "SNMP — данные сетевого оборудования" in page.locator(".ws-snmp-topology-panel h3").inner_text()
        _assert_no_page_overflow(page, width)

        extras.click()
        page.get_by_role("button", name="SSH-сбор данных").click()
        page.locator(".ws-ssh-topology-panel").wait_for(state="visible")
        assert page.locator('script[data-ws-topology-extra="ssh"]').count() == 1
        assert calls["ssh_script"] == 1
        assert not page.locator(".ws-snmp-topology-panel").is_visible()
        assert "SSH — данные Linux/OpenWrt" in page.locator(".ws-ssh-topology-panel h3").inner_text()
        _assert_no_page_overflow(page, width)

        page.get_by_role("button", name="Топология").click()
        assert not page.locator(".ws-snmp-topology-panel").is_visible()
        assert not page.locator(".ws-ssh-topology-panel").is_visible()
        _assert_no_page_overflow(page, width)
    finally:
        browser.close()
        instance.stop()


@pytest.mark.parametrize("viewport", [(480, 320), (1280, 900)])
def test_analysis_workspaces_stay_inside_kiosk_and_web_viewports(viewport):
    width, height = viewport
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": width, "height": height})
        _load_workspace(page)

        traffic = page.locator("#traffic-analysis-modal")
        traffic.evaluate("node => { node.hidden = false; }")
        _assert_element_inside_viewport(page, ".traffic-analysis-card", width)
        _assert_no_page_overflow(page, width)
        traffic.evaluate("node => { node.hidden = true; }")

        correlated = page.locator("#global-analysis-modal")
        correlated.evaluate("node => { node.hidden = false; }")
        _assert_element_inside_viewport(page, ".global-analysis-card", width)
        _assert_no_page_overflow(page, width)
    finally:
        browser.close()
        instance.stop()
