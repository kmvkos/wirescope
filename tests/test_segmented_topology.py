from topology.segmented import _decorate_segments, _drop_invalid_host_default_route


def _base_topology():
    return {
        "audit": {"id": "audit-1", "interface": "ens37", "scope": {}},
        "nodes": [
            {
                "id": "wirescope:ens37",
                "kind": "wirescope",
                "label": "WireScope · ens37",
                "roles": ["sensor"],
                "addresses": ["10.11.11.128"],
                "provenance": ["environment"],
                "confidence": "confirmed",
            },
            {
                "id": "asset:host",
                "kind": "asset",
                "label": "10.11.11.37",
                "roles": [],
                "addresses": ["10.11.11.37"],
                "provenance": ["inventory"],
                "confidence": "confirmed",
            },
            {
                "id": "endpoint:192.168.32.2",
                "kind": "endpoint",
                "label": "192.168.32.2",
                "roles": ["gateway"],
                "addresses": ["192.168.32.2"],
                "provenance": ["default-route"],
                "confidence": "confirmed",
            },
        ],
        "edges": [
            {
                "id": "edge:1",
                "source": "wirescope:ens37",
                "target": "endpoint:192.168.32.2",
                "relation": "default_gateway",
                "confidence": "confirmed",
                "provenance": ["default-route"],
            }
        ],
        "summary": {},
    }


def test_host_default_route_from_another_interface_is_removed():
    topology = _base_topology()
    confirmed = {
        "targets": ["10.11.11.0/24"],
        "route_context": {
            "interface": "ens37",
            "routes": [
                {
                    "target": "10.11.11.0/24",
                    "representative_address": "10.11.11.1",
                    "interface": "ens37",
                    "source_address": "10.11.11.128",
                    "gateway": None,
                    "directly_connected": True,
                }
            ],
        },
    }

    _drop_invalid_host_default_route(
        topology,
        interface="ens37",
        confirmed_scope=confirmed,
    )

    assert topology["edges"] == []
    assert all(node["id"] != "endpoint:192.168.32.2" for node in topology["nodes"])


def test_segment_model_separates_subnets_and_uses_resolved_gateway():
    topology = _base_topology()
    topology["nodes"] = topology["nodes"][:2] + [
        {
            "id": "asset:second",
            "kind": "asset",
            "label": "10.11.12.42",
            "roles": [],
            "addresses": ["10.11.12.42"],
            "provenance": ["inventory"],
            "confidence": "confirmed",
        }
    ]
    topology["edges"] = []
    confirmed = {
        "targets": ["10.11.11.0/24", "10.11.12.0/24"],
        "route_context": {
            "interface": "ens37",
            "routes": [
                {
                    "target": "10.11.11.0/24",
                    "representative_address": "10.11.11.1",
                    "interface": "ens37",
                    "source_address": "10.11.11.128",
                    "gateway": None,
                    "directly_connected": True,
                },
                {
                    "target": "10.11.12.0/24",
                    "representative_address": "10.11.12.1",
                    "interface": "ens37",
                    "source_address": "10.11.11.128",
                    "gateway": "10.11.11.1",
                    "directly_connected": False,
                },
            ],
        },
    }

    _decorate_segments(topology, confirmed_scope=confirmed)

    segments = {item["network"]: item for item in topology["segments"]}
    assert set(segments) == {"10.11.11.0/24", "10.11.12.0/24"}
    assert "asset:host" in segments["10.11.11.0/24"]["members"]
    assert "asset:second" in segments["10.11.12.0/24"]["members"]
    assert segments["10.11.12.0/24"]["gateways"] == ["10.11.11.1"]
    gateway_edges = [edge for edge in topology["edges"] if edge["relation"] == "segment_gateway"]
    assert len(gateway_edges) == 1
    assert gateway_edges[0]["layer"] == "l3"
    assert gateway_edges[0]["segment_id"] == "segment:10.11.12.0/24"
