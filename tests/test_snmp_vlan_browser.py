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


def _topology():
    return {
        "schema": "network-topology",
        "schema_version": 3,
        "audit": {"id": "audit-1", "interface": "eth0", "profile": "deep", "status": "completed"},
        "summary": {"nodes": 3, "edges": 2, "segments": 1},
        "snmp_topology": {
            "devices": 1,
            "port_links": 1,
            "lldp_links": 0,
            "interface_nodes": 1,
            "neighbor_links": 1,
        },
        "segments": [
            {
                "id": "segment:10.0.10.0/24",
                "network": "10.0.10.0/24",
                "members": ["asset:switch", "asset:host"],
                "gateways": [],
            }
        ],
        "nodes": [
            {
                "id": "asset:switch",
                "kind": "network-device",
                "label": "core-sw",
                "roles": ["network-device", "snmp-managed"],
                "addresses": ["10.0.10.1"],
                "segment_ids": ["segment:10.0.10.0/24"],
                "confidence": "observed",
                "provenance": ["credentialed-snmp"],
                "snmp_vlans": [
                    {"vlan_id": 10, "name": "users"},
                    {"vlan_id": 20, "name": "servers"},
                ],
                "snmp_interfaces": [
                    {
                        "ifindex": 101,
                        "name": "Gi1/0/5",
                        "pvid": 10,
                        "vlan_ids": [10],
                        "tagged_vlans": [],
                        "untagged_vlans": [10],
                        "port_mode": "access",
                    },
                    {
                        "ifindex": 124,
                        "name": "Gi1/0/24",
                        "pvid": 1,
                        "vlan_ids": [10, 20],
                        "tagged_vlans": [10, 20],
                        "untagged_vlans": [],
                        "port_mode": "trunk",
                    },
                ],
            },
            {
                "id": "asset:host",
                "kind": "asset",
                "label": "host-01",
                "roles": [],
                "addresses": ["10.0.10.50"],
                "mac": "00:11:22:33:44:55",
                "vlan_ids": [10],
                "segment_ids": ["segment:10.0.10.0/24"],
                "confidence": "observed",
                "provenance": ["snmp-qbridge-fdb"],
            },
            {
                "id": "snmp-interface:10.0.10.1:124:10.0.20.1",
                "kind": "network-interface",
                "label": "Vlan20 · 10.0.20.1/24",
                "roles": ["router-interface"],
                "addresses": ["10.0.20.1/24"],
                "vlan_ids": [20],
                "tagged_vlans": [20],
                "untagged_vlans": [],
                "parent_device_id": "asset:switch",
                "segment_ids": ["segment:10.0.20.0/24"],
                "confidence": "observed",
                "provenance": ["credentialed-snmp-ip-interface"],
            },
        ],
        "edges": [
            {
                "id": "edge:port",
                "source": "asset:switch",
                "target": "asset:host",
                "relation": "layer2_neighbor",
                "mapping_type": "switch_port",
                "layer": "l2",
                "confidence": "observed",
                "provenance": ["q-bridge-fdb"],
                "vlan_ids": [10],
                "port_vlans": [10],
                "untagged_vlans": [10],
                "tagged_vlans": [],
                "port_pvid": 10,
                "port_mode": "access",
            },
            {
                "id": "edge:if20",
                "source": "asset:switch",
                "target": "snmp-interface:10.0.10.1:124:10.0.20.1",
                "relation": "routed_interface",
                "mapping_type": "snmp_ip_interface",
                "layer": "l3",
                "confidence": "observed",
                "provenance": ["credentialed-snmp-ip-interface"],
                "vlan_ids": [20],
                "tagged_vlans": [20],
                "untagged_vlans": [],
            },
        ],
        "warnings": [],
    }


def _global():
    return {
        "schema": "network-topology-global",
        "schema_version": 2,
        "summary": {"nodes": 0, "edges": 0, "segments": 0},
        "nodes": [],
        "edges": [],
        "segments": [],
        "warnings": [],
    }


def test_snmp_vlan_focus_renders_evidence_ports_graph_and_json_download():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        fixtures = {
            "/api/v1/audits/audit-1/topology": _topology(),
            "/api/v1/topology/global?limit=100": _global(),
            "/api/v1/traffic-analysis?limit=100": {"items": []},
            "/api/v1/auth/me": {"username": "auditor", "role": "auditor"},
        }
        page.set_content("<!doctype html><html><body><div id='root'></div></body></html>")
        page.evaluate(
            """
            fixtures => {
                window.__fixtures = fixtures;
                window.fetch = async input => {
                    const url = new URL(String(input), "http://wirescope.local");
                    const key = `${url.pathname}${url.search}`;
                    const document = window.__fixtures[key];
                    if (document === undefined) {
                        return new Response(JSON.stringify({detail: {message: `Missing fixture: ${key}`}}), {
                            status: 404,
                            headers: {"Content-Type": "application/json"},
                        });
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
        frontend = Path(__file__).resolve().parents[1] / "frontend"
        page.add_script_tag(path=str(frontend / "topology.js"))
        page.add_script_tag(path=str(frontend / "snmp_topology.js"))
        page.evaluate(
            """async () => {
                await window.WireScopeTopology.render(document.querySelector("#root"), "audit-1");
            }"""
        )

        root = page.locator("#root")
        panel = root.locator(".ws-snmp-topology-panel")
        assert panel.count() == 1
        assert "1 L3 IF" in panel.locator(".ws-snmp-metric").inner_text()
        selector = panel.locator(".ws-snmp-vlan-explorer select")
        assert selector.count() == 1
        assert selector.locator("option").count() == 3
        assert "VLAN 10 · users" in selector.locator("option").nth(1).inner_text()
        assert "VLAN 20 · servers" in selector.locator("option").nth(2).inner_text()

        selector.select_option("10")
        assert "VLAN 10:" in panel.locator(".ws-snmp-vlan-explorer .ws-snmp-status").inner_text()
        assert panel.locator(".ws-snmp-vlan-port").count() == 2  # access port + trunk membership
        port_text = " ".join(panel.locator(".ws-snmp-vlan-port").all_inner_texts())
        assert "Gi1/0/5" in port_text
        assert "access" in port_text
        assert "untagged 10" in port_text
        assert panel.locator(".ws-snmp-vlan-svg").count() == 1
        assert panel.locator(".ws-snmp-vlan-svg .ws-topology-node").count() >= 2

        with page.expect_download() as download_info:
            panel.get_by_role("button", name="Скачать VLAN JSON").click()
        download = download_info.value
        assert download.suggested_filename == "wirescope-vlan-10.json"
        payload = json.loads(Path(download.path()).read_text(encoding="utf-8"))
        assert payload["vlan_id"] == 10
        assert any(node["id"] == "asset:host" for node in payload["nodes"])
        assert any(edge["id"] == "edge:port" for edge in payload["edges"])

        selector.select_option("20")
        port_text = " ".join(panel.locator(".ws-snmp-vlan-port").all_inner_texts())
        assert "Gi1/0/24" in port_text
        assert "trunk" in port_text
        assert "tagged 10,20" in port_text
    finally:
        browser.close()
        instance.stop()
