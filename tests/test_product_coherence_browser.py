from __future__ import annotations

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


def _load_workspace(page) -> None:
    page.set_content(
        """
        <!doctype html><html lang="ru"><body>
        <div class="app"><main><section class="screen">
          <div id="legacy-findings-label">Слабые места</div>
          <div id="legacy-vlan-note">Тегов 802.1Q не видно. Access-порт часто без тега — ID неизвестен.</div>
          <div class="ws-insights-tabs"><button class="primary">Сводка</button></div>
          <select id="ws-audit-select"><option value="audit-1" selected>audit-1</option></select>
          <div id="ws-insights-body">
            <section class="ws-snmp-topology-panel card">
              <div class="ws-snmp-heading"><h3>SNMP · физическая топология</h3></div>
              <form class="ws-snmp-form"><label>Target<input value="10.0.0.1"></label><button>Запустить SNMP</button></form>
            </section>
            <section class="ws-ssh-topology-panel card">
              <div class="ws-ssh-heading"><h3>SSH · management topology</h3></div>
              <form class="ws-ssh-form"><label>Target<input value="10.0.0.1"></label><button>Запустить read-only SSH</button></form>
            </section>
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
        _load_workspace(page)

        assert page.locator("#legacy-findings-label").inner_text() == "Проблемы"
        assert "Порт доступа" in page.locator("#legacy-vlan-note").inner_text()
        assert page.get_by_role("button", name="Топология").count() == 1
        assert page.get_by_role("button", name="История топологии").count() == 1
        extras = page.get_by_role("button", name="Дополнительно")
        assert extras.count() == 1

        assert not page.locator(".ws-snmp-topology-panel").is_visible()
        assert not page.locator(".ws-ssh-topology-panel").is_visible()
        _assert_no_page_overflow(page, width)

        extras.click()
        assert page.get_by_role("button", name="SNMP-опрос").is_visible()
        assert page.get_by_role("button", name="SSH-сбор данных").is_visible()
        _assert_no_page_overflow(page, width)

        page.get_by_role("button", name="SNMP-опрос").click()
        assert page.locator(".ws-snmp-topology-panel").is_visible()
        assert not page.locator(".ws-ssh-topology-panel").is_visible()
        assert "SNMP — данные сетевого оборудования" in page.locator(".ws-snmp-topology-panel h3").inner_text()
        _assert_no_page_overflow(page, width)

        extras.click()
        page.get_by_role("button", name="SSH-сбор данных").click()
        assert not page.locator(".ws-snmp-topology-panel").is_visible()
        assert page.locator(".ws-ssh-topology-panel").is_visible()
        assert "SSH — данные Linux/OpenWrt" in page.locator(".ws-ssh-topology-panel h3").inner_text()
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
