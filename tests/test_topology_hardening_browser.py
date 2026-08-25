from __future__ import annotations

from pathlib import Path

import pytest

from topology.completeness import decorate_completeness
from topology.presentation import decorate_presentation


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


def _audit():
    segment = "segment:10.11.11.0/24"
    data = {
        "schema": "network-topology",
        "schema_version": 3,
        "audit": {"id": "audit-1", "interface": "ens37", "profile": "deep"},
        "segments": [{
            "id": segment,
            "network": "10.11.11.0/24",
            "members": ["wirescope:ens37", "asset:gw", "asset:host", "endpoint:broadcast"],
            "gateways": ["10.11.11.11"],
            "interface": "ens37",
        }],
        "nodes": [
            {"id": "wirescope:ens37", "kind": "wirescope", "label": "WireScope · ens37", "roles": ["sensor"], "addresses": ["10.11.11.124/24"], "segment_ids": [segment], "confidence": "confirmed", "provenance": ["environment"]},
            {"id": "asset:gw", "kind": "asset", "label": "10.11.11.11", "roles": ["gateway", "router"], "addresses": ["10.11.11.11"], "segment_ids": [segment], "state": "responsive", "confidence": "confirmed", "provenance": ["inventory", "dhcp-lease-router"]},
            {"id": "neighbor:ap", "kind": "network-device", "label": "Netcraze-7032", "roles": ["network-neighbor"], "addresses": ["fe80::1"], "segment_ids": [], "confidence": "confirmed", "provenance": ["lldp"]},
            {"id": "asset:host", "kind": "asset", "label": "host", "names": ["host.local"], "roles": [], "addresses": ["10.11.11.82", "fe80::82"], "segment_ids": [segment], "state": "responsive", "services": [{"protocol": "tcp", "port": 443, "name": "https"}], "confidence": "confirmed", "provenance": ["inventory"]},
            {"id": "endpoint:external", "kind": "endpoint", "label": "5.188.18.125", "roles": [], "addresses": ["5.188.18.125"], "segment_ids": [], "confidence": "observed", "provenance": ["pcap"]},
            {"id": "endpoint:broadcast", "kind": "endpoint", "label": "10.11.11.255", "roles": [], "addresses": ["10.11.11.255"], "segment_ids": [segment], "confidence": "observed", "provenance": ["pcap"]},
            {"id": "endpoint:linklocal", "kind": "endpoint", "label": "fe80::dead:beef", "roles": [], "addresses": ["fe80::dead:beef"], "segment_ids": [], "confidence": "observed", "provenance": ["pcap"]},
        ],
        "edges": [
            {"id": "edge:gateway", "source": "wirescope:ens37", "target": "asset:gw", "relation": "segment_gateway", "layer": "l3", "confidence": "confirmed", "provenance": ["dhcp-lease-router"], "segment_id": segment, "segment_ids": [segment]},
            {"id": "edge:lldp", "source": "wirescope:ens37", "target": "neighbor:ap", "relation": "layer2_neighbor", "layer": "l2", "confidence": "confirmed", "provenance": ["lldp"], "segment_ids": [segment]},
            {"id": "edge:traffic", "source": "asset:host", "target": "endpoint:external", "relation": "communication", "layer": "traffic", "confidence": "observed", "provenance": ["pcap"], "segment_ids": [segment], "packets": 295, "bytes": 30000},
            {"id": "edge:broadcast", "source": "asset:host", "target": "endpoint:broadcast", "relation": "communication", "layer": "traffic", "confidence": "observed", "provenance": ["pcap"], "segment_ids": [segment], "packets": 4},
        ],
        "overlay": {"traffic_analysis_job_id": "pcap-job", "interface": "ens37", "frame_count": 295},
        "summary": {"nodes": 7, "edges": 4, "segments": 1, "confidence": {"confirmed": 2, "observed": 2}},
        "warnings": [],
    }
    return decorate_completeness(decorate_presentation(data))


def _global():
    data = {
        "schema": "network-topology-global",
        "schema_version": 2,
        "segments": [],
        "nodes": [
            {"id": "segment:10.11.11.0/24", "kind": "segment", "label": "10.11.11.0/24", "roles": ["subnet"], "confidence": "confirmed", "provenance": ["retained-audits"]},
            {"id": "gateway:10.11.11.11", "kind": "endpoint", "label": "10.11.11.11", "roles": ["gateway", "router"], "addresses": ["10.11.11.11"], "confidence": "confirmed", "provenance": ["confirmed-scope-route"]},
        ],
        "edges": [{"id": "global:1", "source": "segment:10.11.11.0/24", "target": "gateway:10.11.11.11", "relation": "segment_gateway", "layer": "l3", "confidence": "confirmed", "provenance": ["confirmed-scope-route"]}],
        "warnings": [],
    }
    return decorate_completeness(decorate_presentation(data))


def _load(page):
    fixtures = {
        "/api/v1/audits/audit-1/topology": _audit(),
        "/api/v1/topology/global?limit=100": _global(),
        "/api/v1/traffic-analysis?limit=100": {"items": []},
    }
    page.set_content("<!doctype html><html><body><div id='root'></div></body></html>")
    page.evaluate(
        """
        fixtures => {
            window.__fixtures = fixtures;
            window.fetch = async input => {
                const url = new URL(String(input), "http://wirescope.local");
                const key = `${url.pathname}${url.search}`;
                const data = window.__fixtures[key];
                if (data === undefined) return new Response(JSON.stringify({detail:{message:`missing ${key}`}}), {status:404, headers:{"Content-Type":"application/json"}});
                return new Response(JSON.stringify(data), {status:200, headers:{"Content-Type":"application/json"}});
            };
        }
        """,
        fixtures,
    )
    root = Path(__file__).resolve().parents[1]
    page.add_script_tag(path=str(root / "frontend" / "topology.js"))
    page.add_script_tag(path=str(root / "frontend" / "topology_hardening.js"))
    page.evaluate("async () => window.WireScopeTopology.render(document.querySelector('#root'), 'audit-1')")


def test_hardened_topology_defaults_to_structural_map_and_explains_coverage():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        _load(page)
        root = page.locator("#root")

        assert page.evaluate("window.WireScopeTopology.version") == "m11.4"
        assert root.locator(".ws-topology-coverage").count() == 1
        assert root.locator(".ws-coverage-card").count() == 7
        assert "gateway" in root.locator(".ws-topology-claim-line").inner_text()

        selects = root.locator(".ws-topology-controls select")
        assert selects.count() == 5
        assert selects.nth(0).input_value() == "audit"
        assert selects.nth(2).input_value() == "structural"
        assert root.locator(".ws-topology-region").count() == 1
        assert root.locator(".ws-topology-node").filter(has_text="5.188.18.125").count() == 0
        assert root.locator(".ws-topology-node").filter(has_text="10.11.11.255").count() == 0
        assert root.locator(".ws-topology-node").filter(has_text="fe80::dead").count() == 0
        assert root.locator(".ws-topology-rel-communication").count() == 0
        assert "скрыто broadcast/multicast: 1" in root.locator(".ws-topology-meta").inner_text()

        zoom = root.locator(".ws-topology-zoom-value")
        assert zoom.inner_text() == "100%"
        root.locator("[data-zoom='in']").click()
        assert zoom.inner_text() == "120%"
        assert "scale(1.2)" in root.locator(".ws-topology-viewport").get_attribute("transform")

        selects.nth(2).select_option("traffic")
        assert root.locator(".ws-topology-node").filter(has_text="5.188.18.125").count() == 1
        assert root.locator(".ws-topology-rel-communication").count() == 1

        selects.nth(2).select_option("structural")
        with page.expect_download() as info:
            root.get_by_role("button", name="Скачать схему SVG").click()
        text = Path(info.value.path()).read_text(encoding="utf-8")
        assert 'width="1600"' in text
        assert "translate(0 0) scale(1)" in text
        assert "5.188.18.125" not in text
    finally:
        browser.close()
        instance.stop()
