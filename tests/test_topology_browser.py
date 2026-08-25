from __future__ import annotations

from copy import deepcopy
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


def _audit_topology() -> dict:
    segment_a = "segment:10.0.0.0/24"
    segment_b = "segment:10.0.1.0/24"
    nodes = [
        {
            "id": "wirescope:eth0",
            "kind": "wirescope",
            "label": "WireScope · eth0",
            "roles": ["sensor"],
            "addresses": ["10.0.0.50/24"],
            "segment_ids": [segment_a],
            "confidence": "confirmed",
            "provenance": ["environment"],
        },
        {
            "id": segment_a,
            "kind": "segment",
            "label": "10.0.0.0/24",
            "network": "10.0.0.0/24",
            "roles": ["subnet"],
            "segment_ids": [segment_a],
            "confidence": "confirmed",
            "provenance": ["confirmed-scope-route"],
        },
        {
            "id": segment_b,
            "kind": "segment",
            "label": "10.0.1.0/24",
            "network": "10.0.1.0/24",
            "roles": ["subnet"],
            "segment_ids": [segment_b],
            "confidence": "confirmed",
            "provenance": ["confirmed-scope-route"],
        },
        {
            "id": "asset:gateway",
            "kind": "asset",
            "label": "Gateway",
            "roles": ["gateway", "router", "network-device"],
            "addresses": ["10.0.0.1"],
            "segment_ids": [segment_a],
            "confidence": "confirmed",
            "provenance": ["inventory", "confirmed-scope-route"],
        },
        {
            "id": "asset:switch",
            "kind": "network-device",
            "label": "Switch-01",
            "roles": ["network-device", "network-neighbor"],
            "addresses": ["10.0.0.2"],
            "segment_ids": [segment_a],
            "confidence": "observed",
            "provenance": ["lldp"],
        },
        {
            "id": "asset:host-a",
            "kind": "asset",
            "label": "Host-A",
            "roles": [],
            "addresses": ["10.0.0.10"],
            "segment_ids": [segment_a],
            "confidence": "confirmed",
            "provenance": ["inventory"],
            "services": [{"protocol": "tcp", "port": 443, "name": "https"}],
        },
        {
            "id": "asset:host-b",
            "kind": "asset",
            "label": "Host-B",
            "roles": [],
            "addresses": ["10.0.1.20"],
            "segment_ids": [segment_b],
            "confidence": "confirmed",
            "provenance": ["inventory"],
        },
        {
            "id": "endpoint:8.8.8.8",
            "kind": "endpoint",
            "label": "8.8.8.8",
            "roles": [],
            "addresses": ["8.8.8.8"],
            "segment_ids": [],
            "confidence": "observed",
            "provenance": ["pcap"],
        },
        {
            "id": "group:224.0.0.251",
            "kind": "multicast-group",
            "label": "224.0.0.251",
            "roles": [],
            "addresses": ["224.0.0.251"],
            "segment_ids": [],
            "confidence": "observed",
            "provenance": ["pcap"],
        },
    ]
    edges = [
        {
            "id": "edge:l3-gateway",
            "source": segment_a,
            "target": "asset:gateway",
            "relation": "segment_gateway",
            "layer": "l3",
            "confidence": "confirmed",
            "provenance": ["confirmed-scope-route"],
            "segment_id": segment_a,
            "segment_ids": [segment_a],
        },
        {
            "id": "edge:l2-switch",
            "source": "asset:switch",
            "target": "asset:host-a",
            "relation": "layer2_neighbor",
            "layer": "l2",
            "confidence": "observed",
            "provenance": ["credentialed-snmp", "snmp-fdb"],
            "segment_ids": [segment_a],
            "port_id": "Gi1/0/3",
        },
        {
            "id": "edge:route-target",
            "source": "asset:gateway",
            "target": segment_b,
            "relation": "route_target",
            "layer": "l3",
            "confidence": "observed",
            "provenance": ["route-trace"],
            "segment_ids": [segment_a, segment_b],
        },
        {
            "id": "edge:traffic",
            "source": "asset:host-a",
            "target": "endpoint:8.8.8.8",
            "relation": "communication",
            "layer": "traffic",
            "confidence": "observed",
            "provenance": ["pcap"],
            "segment_ids": [segment_a],
            "packets": 120,
            "bytes": 45000,
            "packets_a_to_b": 80,
            "packets_b_to_a": 40,
            "protocols": ["TLS/HTTPS"],
            "ports": ["tcp/443"],
        },
        {
            "id": "edge:multicast",
            "source": "asset:host-a",
            "target": "group:224.0.0.251",
            "relation": "communication",
            "layer": "traffic",
            "confidence": "observed",
            "provenance": ["pcap"],
            "segment_ids": [segment_a],
            "packets": 5,
            "bytes": 600,
            "packets_a_to_b": 5,
            "packets_b_to_a": 0,
            "protocols": ["mDNS"],
            "ports": ["udp/5353"],
        },
    ]
    return {
        "schema": "network-topology",
        "schema_version": 3,
        "model": "routed-segment-aware",
        "audit": {"id": "audit-1", "interface": "eth0", "profile": "deep", "status": "completed"},
        "summary": {"nodes": len(nodes), "edges": len(edges), "segments": 2, "confidence": {"confirmed": 1, "observed": 4}},
        "segments": [
            {
                "id": segment_a,
                "kind": "subnet",
                "label": "10.0.0.0/24",
                "network": "10.0.0.0/24",
                "members": ["wirescope:eth0", "asset:gateway", "asset:switch", "asset:host-a"],
                "gateways": ["10.0.0.1"],
                "interface": "eth0",
            },
            {
                "id": segment_b,
                "kind": "subnet",
                "label": "10.0.1.0/24",
                "network": "10.0.1.0/24",
                "members": ["asset:host-b"],
                "gateways": [],
                "interface": "eth0",
            },
        ],
        "nodes": nodes,
        "edges": edges,
        "warnings": [],
    }


def _global_topology() -> dict:
    return {
        "schema": "network-topology-global",
        "schema_version": 2,
        "model": "cross-audit-routed-segments",
        "summary": {"nodes": 3, "edges": 2, "segments": 2, "confidence": {"confirmed": 2}},
        "nodes": [
            {"id": "segment:10.0.0.0/24", "kind": "segment", "label": "10.0.0.0/24", "roles": ["subnet"], "confidence": "confirmed", "provenance": ["retained-audits"]},
            {"id": "segment:10.0.1.0/24", "kind": "segment", "label": "10.0.1.0/24", "roles": ["subnet"], "confidence": "confirmed", "provenance": ["retained-audits"]},
            {"id": "gateway:10.0.0.1", "kind": "endpoint", "label": "10.0.0.1", "roles": ["gateway", "router"], "addresses": ["10.0.0.1"], "confidence": "confirmed", "provenance": ["confirmed-scope-route"]},
        ],
        "edges": [
            {"id": "global:1", "source": "segment:10.0.0.0/24", "target": "gateway:10.0.0.1", "relation": "segment_gateway", "layer": "l3", "confidence": "confirmed", "provenance": ["confirmed-scope-route"]},
            {"id": "global:2", "source": "segment:10.0.1.0/24", "target": "gateway:10.0.0.1", "relation": "segment_gateway", "layer": "l3", "confidence": "confirmed", "provenance": ["confirmed-scope-route"]},
        ],
        "segments": [],
        "warnings": [],
    }


def _load_topology(page, audit: dict) -> None:
    fixtures = {
        "/api/v1/audits/audit-1/topology": audit,
        "/api/v1/topology/global?limit=100": _global_topology(),
        "/api/v1/traffic-analysis?limit=100": {"items": []},
    }
    page.set_content("<!doctype html><html><body><div id='root'></div></body></html>")
    page.evaluate(
        """
        fixtures => {
            window.__wsTopologyFixtures = fixtures;
            window.fetch = async input => {
                const url = new URL(String(input), "http://wirescope.local");
                const key = `${url.pathname}${url.search}`;
                const document = window.__wsTopologyFixtures[key];
                if (document === undefined) {
                    return new Response(
                        JSON.stringify({detail: {message: `Missing topology fixture: ${key}`}}),
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
    script = Path(__file__).resolve().parents[1] / "frontend" / "topology.js"
    page.add_script_tag(path=str(script))
    page.evaluate(
        """async () => {
            await window.WireScopeTopology.render(document.querySelector("#root"), "audit-1");
        }"""
    )


def test_topology_ui_renders_filters_focus_and_zoom():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        _load_topology(page, _audit_topology())

        root = page.locator("#root")
        selects = root.locator(".ws-topology-controls select")
        assert selects.count() == 5
        assert root.locator(".ws-topology-svg").count() == 1

        # Global is the default view. Switch to the audit-specific map to expose
        # segment regions and the full L2/L3/Traffic control surface.
        selects.nth(0).select_option("audit")
        assert root.locator(".ws-topology-region").count() == 2
        assert root.locator(".ws-topology-node").count() >= 7

        zoom_value = root.locator(".ws-topology-zoom-value")
        assert zoom_value.inner_text() == "100%"
        root.locator("[data-zoom='in']").click()
        assert zoom_value.inner_text() == "120%"
        assert "scale(1.2)" in root.locator(".ws-topology-viewport").get_attribute("transform")
        root.locator("[data-zoom='fit']").click()
        assert zoom_value.inner_text() == "100%"

        # L3 must hide observed traffic while retaining route/gateway evidence.
        selects.nth(2).select_option("l3")
        assert root.locator(".ws-topology-rel-communication").count() == 0
        assert root.locator(".ws-topology-rel-segment_gateway").count() == 1

        # Confidence filtering is applied to edges, not merely to labels.
        selects.nth(2).select_option("general")
        selects.nth(3).select_option("confirmed")
        assert root.locator(".ws-topology-observed").count() == 0
        assert root.locator(".ws-topology-confirmed").count() >= 1
        selects.nth(3).select_option("all")

        # Multicast/broadcast is intentionally hidden until the operator asks.
        assert root.locator(".ws-topology-node-multicast-group").count() == 0
        root.locator(".ws-topology-check input[type='checkbox']").first.check()
        assert root.locator(".ws-topology-node-multicast-group").count() == 1

        # Double-clicking a subnet focuses the corresponding select value.
        first_region = root.locator(".ws-topology-region").first
        first_region.dblclick()
        assert selects.nth(1).input_value() == "segment:10.0.0.0/24"

        host_a = root.locator(".ws-topology-node").filter(has_text="Host-A")
        assert host_a.count() == 1
        host_a.click()
        details = root.locator(".ws-topology-details")
        assert "Host-A" in details.inner_text()
        assert "10.0.0.10" in details.inner_text()
        assert "tcp/443 https" in details.inner_text()
    finally:
        browser.close()
        instance.stop()


def test_topology_ui_bounds_large_maps_to_120_visible_nodes():
    audit = deepcopy(_audit_topology())
    segment_id = "segment:10.0.0.0/24"
    for index in range(130):
        node_id = f"asset:bulk-{index}"
        audit["nodes"].append(
            {
                "id": node_id,
                "kind": "asset",
                "label": f"Bulk-{index:03d}",
                "roles": [],
                "addresses": [f"10.0.0.{100 + (index % 100)}"],
                "segment_ids": [segment_id],
                "confidence": "observed",
                "provenance": ["inventory"],
            }
        )
        audit["segments"][0]["members"].append(node_id)
    audit["summary"]["nodes"] = len(audit["nodes"])

    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        _load_topology(page, audit)
        root = page.locator("#root")
        root.locator(".ws-topology-controls select").nth(0).select_option("audit")
        assert root.locator(".ws-topology-node").count() == 120
        assert "На схеме показано 120 из" in root.inner_text()
    finally:
        browser.close()
        instance.stop()
