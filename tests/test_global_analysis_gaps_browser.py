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


def _page(browser, payload, calls):
    page = browser.new_page(viewport={"width": 480, "height": 320})

    def api(route):
        if route.request.url.endswith("/api/v1/jobs/job-1/global-analysis"):
            calls["result"] += 1
            route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))
            return
        route.fulfill(status=404, content_type="application/json", body="{}")

    page.route("http://wirescope.test/api/v1/**", api)
    page.set_content(
        """
        <!doctype html><html><head><base href="http://wirescope.test/"></head><body>
          <a id="ga-export-json" href="/api/v1/jobs/job-1/global-analysis/export?format=json">JSON</a>
          <section id="ga-content" class="ga-content">
            <section class="ga-section"><h3>Сводка сопоставления</h3></section>
            <section class="ga-section"><h3>Корреляция сохранённых результатов WireScope</h3></section>
            <section class="ga-section"><h3>Согласованность инфраструктурных данных</h3></section>
          </section>
        </body></html>
        """
    )
    page.add_style_tag(path=str(ROOT / "frontend/global_analysis.css"))
    page.add_style_tag(path=str(ROOT / "frontend/global_analysis_gaps.css"))
    page.add_script_tag(path=str(ROOT / "frontend/global_analysis_gaps.js"))
    return page


def test_evidence_gap_cards_render_once_and_fit_kiosk_viewport():
    instance, browser = _browser()
    try:
        calls = {"result": 0}
        payload = {
            "schema": "global-analysis",
            "evidence_gaps": [
                {
                    "id": "gap-1",
                    "category": "infrastructure_gateway",
                    "status": "needs_evidence",
                    "priority": "high",
                    "title": "Шлюз по умолчанию: данных недостаточно для подтверждения",
                    "known_evidence": ["снимок окружения WireScope: 10.0.0.1"],
                    "missing_evidence": ["Для подтверждения нужны как минимум два независимых источника."],
                    "collection_options": [
                        "Снять PCAP на нужном VLAN во время DHCP renew.",
                        "Собрать SNMP/SSH-данные через Топология → Дополнительно.",
                    ],
                    "safe_conclusion": "Шлюз пока подтверждён только одним источником.",
                    "affected": {"count": 1},
                }
            ],
        }
        page = _page(browser, payload, calls)

        section = page.locator(".ga-evidence-gaps")
        section.wait_for(state="visible")
        assert section.get_by_text("Что ещё нужно подтвердить").is_visible()
        assert section.get_by_text("Что уже есть").is_visible()
        assert section.get_by_text("Чего не хватает").is_visible()
        assert section.get_by_text("Как добрать данные").is_visible()
        assert section.get_by_text("Пока корректно утверждать").is_visible()

        sections = page.locator("#ga-content > .ga-section")
        assert "Сводка сопоставления" in sections.nth(0).inner_text()
        assert "Корреляция сохранённых результатов WireScope" in sections.nth(1).inner_text()
        assert "Что ещё нужно подтвердить" in sections.nth(2).inner_text()
        assert "Согласованность инфраструктурных данных" in sections.nth(3).inner_text()

        page.wait_for_timeout(250)
        assert calls["result"] == 1
        assert page.locator(".ga-evidence-gaps").count() == 1
        overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
        assert overflow is False
    finally:
        browser.close()
        instance.stop()


def test_zero_gap_result_is_cached_without_repeat_fetch_on_other_ui_mutations():
    instance, browser = _browser()
    try:
        calls = {"result": 0}
        page = _page(browser, {"schema": "global-analysis", "evidence_gaps": []}, calls)
        page.wait_for_timeout(150)
        assert calls["result"] == 1
        assert page.locator(".ga-evidence-gaps").count() == 0

        page.evaluate(
            """
            () => {
                const section = document.createElement('section');
                section.className = 'ga-section';
                section.textContent = 'Другая часть интерфейса обновилась';
                document.getElementById('ga-content').append(section);
            }
            """
        )
        page.wait_for_timeout(150)
        assert calls["result"] == 1
        assert page.locator(".ga-evidence-gaps").count() == 0
    finally:
        browser.close()
        instance.stop()
