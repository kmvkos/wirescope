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


def test_correlated_assessment_copy_is_localized_only_in_presentation_nodes():
    instance, browser = _browser()
    try:
        page = browser.new_page()
        page.set_content(
            """
            <!doctype html><html lang="ru"><body>
              <div id="global-analysis-modal">
                <ul class="ga-warnings">
                  <li id="warning">Selected traffic analysis does not contain a usable communications graph.</li>
                </ul>
                <details class="ga-evidence">
                  <summary id="lineage">Evidence lineage</summary>
                </details>
                <span class="ga-pill" id="service-status">трафик сервиса наблюдался</span>
                <div class="ga-note" id="cancel-error">Не удалось остановить job: timeout</div>
                <div id="ga-audit-meta">27.08.2026 · deep · eth0 · deadbeef</div>
                <div class="ga-history-item" id="history-meta">CA deadbeef · Traffic feedface · rebuild 01234567</div>

                <div id="raw-div">Traffic Asset deep completed SNMP enrichment host-deep.example</div>
                <div class="ga-table-row"><span id="row-data">srv-Traffic-deep-completed.example · 192.0.2.44</span></div>
                <pre id="raw-pre">Traffic Asset deep completed SNMP enrichment 192.0.2.45</pre>
                <code id="raw-code">Traffic Asset deep completed SNMP enrichment 192.0.2.46</code>
                <select><option id="raw-option">Traffic Asset deep completed SNMP enrichment 192.0.2.47</option></select>
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
        assert page.locator("#ga-audit-meta").inner_text() == "27.08.2026 · глубокий · eth0 · deadbeef"
        assert page.locator("#history-meta").inner_text() == (
            "Корреляция deadbeef · PCAP feedface · пересборка 01234567"
        )

        # Network/evidence values are not generic translation input even when
        # they contain words that are also known presentation tokens.
        assert page.locator("#raw-div").inner_text() == (
            "Traffic Asset deep completed SNMP enrichment host-deep.example"
        )
        assert page.locator("#row-data").inner_text() == (
            "srv-Traffic-deep-completed.example · 192.0.2.44"
        )
        assert page.locator("#raw-pre").inner_text() == (
            "Traffic Asset deep completed SNMP enrichment 192.0.2.45"
        )
        assert page.locator("#raw-code").inner_text() == (
            "Traffic Asset deep completed SNMP enrichment 192.0.2.46"
        )
        assert page.locator("#raw-option").inner_text() == (
            "Traffic Asset deep completed SNMP enrichment 192.0.2.47"
        )
    finally:
        browser.close()
        instance.stop()
