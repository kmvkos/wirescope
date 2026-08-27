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


def test_correlated_assessment_machine_copy_is_normalized_in_dom():
    instance, browser = _browser()
    try:
        page = browser.new_page()
        page.set_content(
            """
            <!doctype html><html lang="ru"><body>
              <div id="global-analysis-modal">
                <div id="warning">Selected traffic analysis does not contain a usable communications graph.</div>
                <div id="lineage">Evidence lineage</div>
                <div id="service-status">трафик сервиса наблюдался</div>
                <div id="cancel-error">Не удалось остановить job: timeout</div>
                <div id="audit-option">27.08.2026 · deep · eth0 · deadbeef</div>
                <div id="history-meta">CA deadbeef · Traffic feedface · rebuild 01234567</div>
              </div>
            </body></html>
            """
        )
        page.add_script_tag(path=str(ROOT / "frontend/product_coherence.js"))

        assert page.locator("#warning").inner_text() == (
            "Выбранный анализ PCAP не содержит пригодного графа коммуникаций; часть корреляции недоступна."
        )
        assert page.locator("#lineage").inner_text() == "Источники и ссылки на доказательства"
        assert page.locator("#service-status").inner_text() == "трафик службы наблюдался"
        assert page.locator("#cancel-error").inner_text() == "Не удалось остановить задание: timeout"
        assert " · Глубокий · " in page.locator("#audit-option").inner_text()
        assert page.locator("#history-meta").inner_text() == (
            "Корреляция deadbeef · PCAP feedface · пересборка 01234567"
        )
    finally:
        browser.close()
        instance.stop()
