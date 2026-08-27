from __future__ import annotations

import json
from pathlib import Path

import pytest


pytestmark = pytest.mark.browser


def _browser():
    playwright = pytest.importorskip("playwright.sync_api")
    instance = playwright.sync_playwright().start()
    try:
        browser = instance.chromium.launch(headless=True)
    except Exception as exc:
        instance.stop()
        pytest.skip(f"Chromium is unavailable: {exc}")
    return instance, browser


def test_topology_history_ui_renders_changes_and_exports_json():
    global_view = {
        "schema": "network-topology-global",
        "partial": False,
        "audits": [
            {
                "id": "audit-new",
                "profile": "deep",
                "interface": "eth0",
                "status": "completed",
                "created_at": "2026-08-25T12:00:00Z",
            },
            {
                "id": "audit-old",
                "profile": "deep",
                "interface": "eth0",
                "status": "completed",
                "created_at": "2026-08-24T12:00:00Z",
            },
        ],
    }
    comparison = {
        "schema": "network-topology-diff",
        "schema_version": 1,
        "baseline": {"audit_id": "audit-old"},
        "current": {"audit_id": "audit-new"},
        "summary": {
            "segments_added": 0,
            "segments_removed": 0,
            "nodes_added": 1,
            "nodes_removed": 0,
            "nodes_changed": 1,
            "edges_added": 0,
            "edges_removed": 0,
            "edges_changed": 1,
        },
        "segments": {"added": [], "removed": []},
        "nodes": {
            "added": [
                {
                    "key": "ip:10.0.0.77",
                    "match_basis": "ip",
                    "kind": "endpoint",
                    "label": "10.0.0.77",
                    "addresses": ["10.0.0.77"],
                    "mac": None,
                    "roles": [],
                    "vlan_ids": [],
                }
            ],
            "removed": [],
            "changed": [
                {
                    "key": "mac:00:11:22:33:44:55",
                    "match_basis": "mac",
                    "before": {"label": "server-01"},
                    "after": {"label": "server-01"},
                    "changes": {"vlan_ids": {"before": [10], "after": [20]}},
                }
            ],
        },
        "edges": {
            "added": [],
            "removed": [],
            "changed": [
                {
                    "key": "layer2_neighbor|switch_port|a|b",
                    "before": {"label": "switch-port"},
                    "after": {"label": "switch-port"},
                    "changes": {"port_name": {"before": "Gi1/0/5", "after": "Gi1/0/8"}},
                }
            ],
        },
        "warnings": [],
    }

    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1200, "height": 900})
        fixtures = {
            "/api/v1/topology/global?limit=100": global_view,
            "/api/v1/audits/audit-new/topology/compare?against=audit-old": comparison,
        }
        page.set_content("<!doctype html><html><body><div id='root'></div></body></html>")
        page.evaluate(
            """
            fixtures => {
                window.__wsTopologyCompareFixtures = fixtures;
                window.fetch = async input => {
                    const url = new URL(String(input), "http://wirescope.local");
                    const key = `${url.pathname}${url.search}`;
                    const document = window.__wsTopologyCompareFixtures[key];
                    if (document === undefined) {
                        return new Response(
                            JSON.stringify({detail: {message: `Missing fixture: ${key}`}}),
                            {status: 404, headers: {"Content-Type": "application/json"}}
                        );
                    }
                    return new Response(JSON.stringify(document), {
                        status: 200,
                        headers: {"Content-Type": "application/json"},
                    });
                };
            }
            """,
            fixtures,
        )
        script = Path(__file__).resolve().parents[1] / "frontend" / "topology_compare.js"
        page.add_script_tag(path=str(script))
        page.evaluate(
            """async () => {
                await window.WireScopeTopologyCompare.render(document.querySelector("#root"), "audit-new");
            }"""
        )

        root = page.locator("#root")
        assert "История топологии" in root.inner_text()
        select = root.locator(".ws-topology-compare-controls select")
        assert select.locator("option").count() == 2
        compare = root.get_by_role("button", name="Сравнить")
        assert compare.is_disabled()

        select.select_option("audit-old")
        assert not compare.is_disabled()
        compare.click()
        root.get_by_role("heading", name="Изменения топологии").wait_for()

        assert "Изменения топологии" in root.inner_text()
        assert "Узлы +" in root.inner_text()
        assert "Узлы Δ" in root.inner_text()
        assert "server-01" in root.inner_text()
        assert "10 → 20" in root.inner_text()
        assert "Gi1/0/5 → Gi1/0/8" in root.inner_text()
        assert "10.0.0.77" in root.inner_text()
        assert "VLAN" in root.inner_text()
        assert "Порт" in root.inner_text()

        with page.expect_download() as download_info:
            root.get_by_role("button", name="Скачать JSON сравнения").click()
        download = download_info.value
        payload = json.loads(Path(download.path()).read_text(encoding="utf-8"))
        assert payload["schema"] == "network-topology-diff"
        assert payload["baseline"]["audit_id"] == "audit-old"
        assert payload["current"]["audit_id"] == "audit-new"
    finally:
        browser.close()
        instance.stop()


def test_topology_history_ui_warns_when_global_audit_list_is_partial():
    instance, browser = _browser()
    try:
        page = browser.new_page()
        fixtures = {
            "/api/v1/topology/global?limit=100": {
                "schema": "network-topology-global",
                "partial": True,
                "source_errors": [{"audit_id": "broken", "code": "source_unavailable"}],
                "audits": [],
            }
        }
        page.set_content("<!doctype html><html><body><div id='root'></div></body></html>")
        page.evaluate(
            """
            fixtures => {
                window.fetch = async input => {
                    const url = new URL(String(input), "http://wirescope.local");
                    const key = `${url.pathname}${url.search}`;
                    return new Response(JSON.stringify(fixtures[key]), {
                        status: 200,
                        headers: {"Content-Type": "application/json"},
                    });
                };
            }
            """,
            fixtures,
        )
        script = Path(__file__).resolve().parents[1] / "frontend" / "topology_compare.js"
        page.add_script_tag(path=str(script))
        page.evaluate(
            """async () => {
                await window.WireScopeTopologyCompare.render(document.querySelector("#root"), "audit-new");
            }"""
        )
        text = page.locator("#root").inner_text()
        assert "Список топологий частичный" in text
        assert "Нет другого сохранённого аудита" in text
    finally:
        browser.close()
        instance.stop()
