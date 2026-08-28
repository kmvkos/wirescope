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


def test_manual_pcap_import_uploads_raw_file_and_marks_imported_session():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 480, "height": 320})
        calls = {"upload": 0, "job": 0}
        uploaded = {"body": b"", "filename": ""}

        def api(route):
            url = route.request.url
            method = route.request.method
            if url.endswith("/api/v1/auth/me"):
                payload = {"username": "auditor", "role": "auditor"}
                status = 200
            elif url.endswith("/api/v1/captures?limit=20"):
                payload = {
                    "items": [{
                        "job_id": "import-1",
                        "audit_id": "audit-import-1",
                        "status": "completed",
                        "source_origin": "imported",
                        "original_filename": "office capture.pcap",
                        "capture_format": "pcap",
                        "pcap_bytes": 24,
                        "pcap_url": "/api/jobs/import-1/pcap",
                        "result_available": True,
                    }]
                }
                status = 200
            elif url.endswith("/api/v1/captures/import") and method == "POST":
                calls["upload"] += 1
                uploaded["body"] = route.request.post_data_buffer or b""
                uploaded["filename"] = route.request.headers.get("x-wirescope-filename", "")
                payload = {
                    "audit_id": "audit-import-1",
                    "job_id": "import-1",
                    "status": "queued",
                    "status_url": "/api/jobs/import-1",
                }
                status = 202
            elif url.endswith("/api/v1/jobs/import-1"):
                calls["job"] += 1
                payload = {
                    "id": "import-1",
                    "status": "completed",
                    "progress": 100,
                    "stage": "completed",
                    "message": "Job completed",
                }
                status = 200
            else:
                route.fulfill(status=404, content_type="application/json", body="{}")
                return
            route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

        page.route("http://wirescope.test/api/v1/**", api)
        page.set_content(
            """
            <!doctype html><html><head><base href="http://wirescope.test/"></head><body>
              <button id="listen-button" type="button" hidden>Прослушивание</button>
              <section id="screen-listen" class="screen">
                <h2>Прослушивание</h2>
                <h3>Сессии</h3>
                <div id="listen-session-list" class="list">
                  <div class="session-row">
                    <button type="button" class="list-item">
                      <strong>Завершён · eth0 · все кадры</strong>
                      <span>— · 24 B</span>
                    </button>
                  </div>
                </div>
              </section>
            </body></html>
            """
        )
        page.add_style_tag(path=str(ROOT / "frontend/style.css"))
        page.add_script_tag(path=str(ROOT / "frontend/pcap_import.js"))

        card = page.locator("#pcap-import-card")
        card.wait_for(state="visible")
        assert card.get_by_role("heading", name="Импорт PCAP").is_visible()
        assert "не выполняет сетевых запросов" in card.inner_text()
        assert "не создаёт активный scope" in card.inner_text()

        # Existing saved-capture row is decorated from explicit source_origin,
        # never from filename or interface heuristics.
        page.wait_for_function(
            "() => document.querySelector('.session-row')?.dataset.pcapOrigin === 'imported'"
        )
        row = page.locator(".session-row")
        assert "Импорт PCAP · office capture.pcap" in row.inner_text()
        assert "PCAP · 24 B" in row.inner_text()

        raw = b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20)
        page.locator("#pcap-import-file").set_input_files({
            "name": "external capture.pcap",
            "mimeType": "application/vnd.tcpdump.pcap",
            "buffer": raw,
        })
        assert "external capture.pcap" in page.locator("#pcap-import-file-meta").inner_text()
        card.get_by_role("button", name="Импортировать PCAP").click()

        page.wait_for_function(
            "() => document.querySelector('#pcap-import-status')?.textContent.includes('импортирован')"
        )
        assert calls["upload"] == 1
        assert calls["job"] >= 1
        assert uploaded["body"] == raw
        assert uploaded["filename"] == "external%20capture.pcap"
        assert "можно анализировать" in page.locator("#pcap-import-status").inner_text()

        overflow = page.evaluate(
            "document.documentElement.scrollWidth > document.documentElement.clientWidth"
        )
        assert overflow is False
    finally:
        browser.close()
        instance.stop()
