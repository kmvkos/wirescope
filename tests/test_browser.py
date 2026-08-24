from pathlib import Path

import pytest

from tests.helpers import http_request

pytestmark = pytest.mark.browser

FRONTEND_SCREENS = (
    "login",
    "environment",
    "interface",
    "scope",
    "profile",
    "confirm",
    "progress",
    "summary",
    "assets",
    "findings",
    "report",
)


def _playwright_chromium():
    playwright = pytest.importorskip("playwright.sync_api")
    try:
        instance = playwright.sync_playwright().start()
    except Exception as exc:
        pytest.skip(f"Playwright is unavailable: {exc}")
    try:
        browser = instance.chromium.launch(headless=True)
    except Exception as exc:
        instance.stop()
        pytest.skip(f"Chromium is unavailable: {exc}")
    return instance, browser


def test_kiosk_viewport_shows_login_and_keeps_touch_targets(api_context, tmp_path):
    playwright = pytest.importorskip("playwright.sync_api")
    html = Path(__file__).resolve().parents[1] / "frontend" / "index.html"
    page_source = html.read_text(encoding="utf-8")
    assert all(f'data-screen="{name}"' in page_source for name in FRONTEND_SCREENS)

    instance, browser = _playwright_chromium()
    try:
        page = browser.new_page(viewport={"width": 480, "height": 320})
        app, _service, _evidence, _environment = api_context
        document = http_request(app, "GET", "/", auth=False).text
        css = http_request(app, "GET", "/static/style.css", auth=False).text
        target = tmp_path / "index.html"
        target.write_text(
            document.replace('href="/static/style.css"', f"href='{(tmp_path / 'style.css').as_uri()}'"),
            encoding="utf-8",
        )
        (tmp_path / "style.css").write_text(css, encoding="utf-8")
        page.goto(target.as_uri())
        login = page.locator("#screen-login")
        assert login.count() == 1
        button = page.locator("#login-form button.primary")
        box = button.bounding_box()
        assert box is not None
        assert box["height"] >= 44
        metrics = page.evaluate(
            """() => ({
                scrollWidth: document.documentElement.scrollWidth,
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight
            })"""
        )
        assert metrics["innerWidth"] == 480
        assert metrics["innerHeight"] == 320
        assert metrics["scrollWidth"] <= 496
    finally:
        browser.close()
        instance.stop()
