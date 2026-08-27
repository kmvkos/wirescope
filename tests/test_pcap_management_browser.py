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


def test_capture_row_can_delete_raw_pcap_without_deleting_history():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 480, "height": 320})
        calls = {"delete": 0}

        def api(route):
            url = route.request.url
            method = route.request.method
            if url.endswith("/api/v1/auth/me"):
                payload = {"username": "auditor", "role": "auditor"}
            elif url.endswith("/api/v1/captures?limit=20"):
                payload = {
                    "items": [{
                        "job_id": "capture-1",
                        "status": "completed",
                        "pcap_url": "/api/jobs/capture-1/pcap",
                        "result_available": True,
                    }]
                }
            elif url.endswith("/api/v1/captures/capture-1/pcap") and method == "DELETE":
                calls["delete"] += 1
                payload = {
                    "job_id": "capture-1",
                    "audit_id": "audit-1",
                    "deleted": True,
                    "already_absent": False,
                    "artifact_count": 1,
                    "pcap_bytes": 1024,
                    "file_cleanup_pending": 0,
                }
            else:
                route.fulfill(status=404, content_type="application/json", body="{}")
                return
            route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

        page.route("http://wirescope.test/api/v1/**", api)
        page.set_content(
            """
            <!doctype html><html><head><base href="http://wirescope.test/"></head><body>
              <div id="listen-session-list">
                <div class="session-row">
                  <span>eth0 · завершён</span>
                  <a href="/api/jobs/capture-1/pcap">Скачать pcap</a>
                  <button class="traffic-analysis-button">Анализировать</button>
                </div>
              </div>
              <section id="screen-listen" class="screen"></section>
              <section id="screen-listen-progress" class="screen" hidden>
                <p id="listen-progress-warning" hidden></p>
                <div class="actions">
                  <button id="listen-download-button">Скачать pcap</button>
                  <button id="listen-done-button">К списку</button>
                </div>
              </section>
            </body></html>
            """
        )
        page.add_style_tag(path=str(ROOT / "frontend/style.css"))
        page.add_script_tag(path=str(ROOT / "frontend/pcap_management.js"))

        row = page.locator("#listen-session-list .session-row")
        delete_button = row.get_by_role("button", name="Удалить PCAP")
        delete_button.wait_for(state="visible")
        delete_button.click()
        page.locator("#pcap-delete-modal").wait_for(state="visible")
        page.locator("#pcap-delete-modal").get_by_role("button", name="Удалить PCAP").click()

        row.locator(".pcap-unavailable-note").wait_for(state="visible")
        assert row.locator(".pcap-unavailable-note").inner_text() == "PCAP удалён"
        assert row.locator(".traffic-analysis-button").count() == 0
        assert row.get_by_text("Скачать pcap").count() == 0
        # The independent progress-screen control is outside the capture row
        # and remains hidden because this synthetic fixture has no active job.
        assert not page.locator("#listen-download-button").is_visible()
        assert calls["delete"] == 1
    finally:
        browser.close()
        instance.stop()
