from __future__ import annotations

from pathlib import Path

import pytest

from topology.completeness import decorate_completeness
from topology.presentation import decorate_presentation
from tests.test_topology_hardening_browser import _audit, _browser, _global


pytestmark = pytest.mark.browser


def _compatible_overlay():
    topology = _audit()
    topology["nodes"].extend(
        [
            {
                "id": "pcap-l3:pcap-job:10.11.11.229",
                "kind": "endpoint",
                "label": "10.11.11.229",
                "roles": ["host"],
                "addresses": ["10.11.11.229"],
                "confidence": "observed",
                "provenance": ["pcap-next-hop"],
            },
            {
                "id": "pcap-l3:pcap-job:10.11.11.1",
                "kind": "network-device",
                "label": "10.11.11.1",
                "roles": ["router", "next-hop"],
                "addresses": ["10.11.11.1"],
                "confidence": "observed",
                "provenance": ["pcap-next-hop"],
            },
        ]
    )
    topology["edges"].append(
        {
            "id": "edge:pcap-next-hop",
            "source": "pcap-l3:pcap-job:10.11.11.229",
            "target": "pcap-l3:pcap-job:10.11.11.1",
            "relation": "l3_next_hop",
            "layer": "l3",
            "confidence": "observed",
            "provenance": ["pcap-next-hop"],
        }
    )
    topology["overlay"] = {
        "traffic_analysis_job_id": "pcap-job",
        "interface": "ens37",
        "compatibility": {
            "status": "compatible",
            "reasons": ["same interface and overlapping private subnet"],
        },
        "correlation": {
            "status": "matched",
            "headline": "Сопоставлено inventory assets: 1 из 2.",
            "matched_asset_count": 1,
            "matches": [{"asset_id": "asset:host", "basis": "exact_mac"}],
            "conflicts": [],
        },
        "discovery": {
            "device_count": 1,
            "lldp_devices": 1,
            "topology_nodes_added": 1,
            "topology_enrichment_skipped": False,
        },
        "next_hop": {
            "candidate_count": 1,
            "high_confidence_count": 1,
            "topology_edges_added": 1,
            "topology_projection_skipped": False,
        },
    }
    return decorate_completeness(decorate_presentation(topology))


def _load(page):
    base = _audit()
    base["overlay"] = None
    overlay = _compatible_overlay()
    fixtures = {
        "/api/v1/audits/audit-1/topology": base,
        "/api/v1/audits/audit-1/topology?traffic_analysis_job_id=pcap-job": overlay,
        "/api/v1/topology/global?limit=100": _global(),
        "/api/v1/traffic-analysis?limit=100": {
            "items": [
                {
                    "job_id": "pcap-job",
                    "capture_job_id": "capture-job",
                    "interface": "ens37",
                }
            ]
        },
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
                if (data === undefined) {
                    return new Response(
                        JSON.stringify({detail:{message:`missing ${key}`}}),
                        {status:404, headers:{"Content-Type":"application/json"}}
                    );
                }
                return new Response(
                    JSON.stringify(data),
                    {status:200, headers:{"Content-Type":"application/json"}}
                );
            };
        }
        """,
        fixtures,
    )
    root = Path(__file__).resolve().parents[1]
    page.add_script_tag(path=str(root / "frontend" / "topology.js"))
    page.add_script_tag(path=str(root / "frontend" / "topology_hardening.js"))
    page.add_script_tag(path=str(root / "frontend" / "topology_evidence_ui.js"))
    page.evaluate(
        "async () => window.WireScopeTopology.render(document.querySelector('#root'), 'audit-1')"
    )


def test_applying_compatible_pcap_keeps_structural_view_and_renders_evidence_panel():
    instance, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1440, "height": 1000)
        _load(page)
        root = page.locator("#root")

        assert page.evaluate("window.WireScopeTopology.version") == "m12-evidence-ui"
        selects = root.locator(".ws-topology-controls select")
        assert selects.nth(2).input_value() == "structural"

        selects.nth(4).select_option("pcap-job")
        root.get_by_role("button", name="Применить PCAP").click()

        page.wait_for_function(
            """() => {
                const panel = document.querySelector('.ws-topology-pcap-evidence');
                return panel && !panel.hidden && panel.textContent.includes('тот же observation domain');
            }"""
        )

        assert selects.nth(2).input_value() == "structural"
        panel = root.locator(".ws-topology-pcap-evidence")
        assert "Совпало assets" in panel.inner_text()
        assert "1" in panel.inner_text()
        assert "L3 next-hop" in panel.inner_text()
        assert "структурную/L3-карту добавлено 1" in panel.inner_text()

        assert root.locator(".ws-topology-node").filter(has_text="10.11.11.1").count() >= 1
        assert root.locator(".ws-topology-node").filter(has_text="10.11.11.229").count() == 1
        assert root.locator(".ws-topology-svg text").filter(has_text="next hop").count() == 1
        assert root.locator(".ws-topology-svg text").filter(has_text="l3_next_hop").count() == 0
    finally:
        browser.close()
        instance.stop()
