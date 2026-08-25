from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_topology_browser import _audit_topology, _browser, _load_topology


pytestmark = pytest.mark.browser


def _audit_with_finding() -> dict:
    audit = _audit_topology()
    host = next(node for node in audit["nodes"] if node["id"] == "asset:host-a")
    host.update(
        {
            "finding_count": 1,
            "findings_truncated": False,
            "findings": [
                {
                    "id": "finding-legacy-tls",
                    "rule_id": "tls.legacy",
                    "title": "Legacy TLS enabled",
                    "severity": "high",
                    "confidence": "confirmed",
                    "status": "open",
                    "service_id": "svc-443",
                    "description": "The service accepts a legacy TLS version.",
                    "recommendation": "Disable legacy TLS protocols.",
                }
            ],
        }
    )
    return audit


def test_topology_asset_card_shows_persisted_findings():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        _load_topology(page, _audit_with_finding())
        root = page.locator("#root")
        root.locator(".ws-topology-controls select").nth(0).select_option("audit")

        host = root.locator(".ws-topology-node").filter(has_text="Host-A")
        assert host.count() == 1
        host.click()

        details = root.locator(".ws-topology-details")
        text = details.inner_text()
        assert "Находки" in text
        assert "Legacy TLS enabled" in text
        assert "HIGH" in text
        assert "open" in text
    finally:
        browser.close()
        instance.stop()


def test_topology_exports_current_filtered_view_as_svg_and_png():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        _load_topology(page, _audit_with_finding())
        root = page.locator("#root")
        selects = root.locator(".ws-topology-controls select")
        selects.nth(0).select_option("audit")
        selects.nth(2).select_option("l3")
        root.locator("[data-zoom='in']").click()

        export_buttons = root.locator(".ws-topology-export-actions button")
        assert export_buttons.count() == 3

        with page.expect_download() as download_info:
            export_buttons.nth(1).click()
        svg_download = download_info.value
        assert svg_download.suggested_filename == "wirescope-topology-audit-1.svg"
        svg_path = Path(svg_download.path())
        svg_text = svg_path.read_text(encoding="utf-8")
        assert "<svg" in svg_text
        assert "scale(1.2)" in svg_text
        assert "ws-topology-rel-segment_gateway" in svg_text
        assert "ws-topology-rel-communication" not in svg_text

        with page.expect_download(timeout=15_000) as download_info:
            export_buttons.nth(2).click()
        png_download = download_info.value
        assert png_download.suggested_filename == "wirescope-topology-audit-1.png"
        png_path = Path(png_download.path())
        assert png_path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert png_path.stat().st_size > 1_000
    finally:
        browser.close()
        instance.stop()
