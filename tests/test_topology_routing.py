from topology.routing import decorate_global_routing_topology, decorate_routed_topology


def _base_topology():
    return {
        "schema": "network-topology",
        "schema_version": 2,
        "model": "segment-aware",
        "nodes": [
            {
                "id": "wirescope:ens37",
                "kind": "wirescope",
                "label": "WireScope · ens37",
                "roles": ["sensor"],
                "addresses": ["10.0.0.50"],
                "provenance": ["environment"],
                "confidence": "confirmed",
            },
            {
                "id": "asset:gw",
                "kind": "asset",
                "label": "router01",
                "roles": ["gateway", "network-device"],
                "addresses": ["10.0.0.1", "10.0.1.1"],
                "segment_ids": ["segment:10.0.0.0/24", "segment:10.0.1.0/24"],
                "provenance": ["nmap"],
                "confidence": "confirmed",
            },
            {
                "id": "asset:server",
                "kind": "asset",
                "label": "server01",
                "roles": [],
                "addresses": ["10.0.0.10", "10.0.1.10"],
                "segment_ids": ["segment:10.0.0.0/24", "segment:10.0.1.0/24"],
                "provenance": ["nmap"],
                "confidence": "confirmed",
            },
        ],
        "edges": [
            {
                "id": "edge:default",
                "source": "wirescope:ens37",
                "target": "asset:gw",
                "relation": "default_gateway",
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["default-route"],
            },
            {
                "id": "edge:gw:a",
                "source": "wirescope:ens37",
                "target": "asset:gw",
                "relation": "segment_gateway",
                "segment_id": "segment:10.0.0.0/24",
                "segment_ids": ["segment:10.0.0.0/24"],
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            },
            {
                "id": "edge:gw:b",
                "source": "wirescope:ens37",
                "target": "asset:gw",
                "relation": "segment_gateway",
                "segment_id": "segment:10.0.1.0/24",
                "segment_ids": ["segment:10.0.1.0/24"],
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            },
        ],
        "segments": [
            {
                "id": "segment:10.0.0.0/24",
                "network": "10.0.0.0/24",
                "family": 4,
                "members": ["asset:gw", "asset:server"],
                "gateways": ["10.0.0.1"],
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            },
            {
                "id": "segment:10.0.1.0/24",
                "network": "10.0.1.0/24",
                "family": 4,
                "members": ["asset:gw", "asset:server"],
                "gateways": ["10.0.1.1"],
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            },
        ],
        "summary": {},
    }


def test_routed_topology_rewires_appliance_gateway_edges_to_segments():
    topology = decorate_routed_topology(_base_topology())
    nodes = {node["id"]: node for node in topology["nodes"]}
    gateway_edges = [edge for edge in topology["edges"] if edge["relation"] == "segment_gateway"]

    assert "segment:10.0.0.0/24" in nodes
    assert "segment:10.0.1.0/24" in nodes
    assert {edge["source"] for edge in gateway_edges} == {
        "segment:10.0.0.0/24",
        "segment:10.0.1.0/24",
    }
    assert all(edge["target"] == "asset:gw" for edge in gateway_edges)
    assert all(not edge["source"].startswith("wirescope:") for edge in gateway_edges)
    assert not any(edge["relation"] == "default_gateway" for edge in topology["edges"])


def test_confirmed_gateway_connecting_two_segments_is_router():
    topology = decorate_routed_topology(_base_topology())
    gateway = next(node for node in topology["nodes"] if node["id"] == "asset:gw")

    assert "router" in gateway["roles"]
    assert gateway["routing_confidence"] == "confirmed"
    assert gateway["connected_segments"] == [
        "segment:10.0.0.0/24",
        "segment:10.0.1.0/24",
    ]
    assert topology["summary"]["routers"] == 1
    assert topology["routing"]["routers"][0]["node_id"] == "asset:gw"


def test_multi_homed_server_is_only_router_candidate():
    topology = decorate_routed_topology(_base_topology())
    server = next(node for node in topology["nodes"] if node["id"] == "asset:server")

    assert "router" not in server["roles"]
    assert "router-candidate" in server["roles"]
    assert server["routing_confidence"] == "inferred"
    assert topology["summary"]["router_candidates"] == 1


def test_global_topology_marks_shared_confirmed_gateway_as_router():
    topology = {
        "schema": "network-topology-global",
        "schema_version": 1,
        "model": "cross-audit-segments",
        "nodes": [
            {"id": "segment:10.0.0.0/24", "kind": "segment", "roles": ["subnet"]},
            {"id": "segment:10.0.1.0/24", "kind": "segment", "roles": ["subnet"]},
            {
                "id": "gateway:10.0.0.1",
                "kind": "endpoint",
                "label": "router01",
                "roles": ["gateway"],
                "provenance": ["confirmed-scope-route"],
            },
        ],
        "edges": [
            {
                "source": "segment:10.0.0.0/24",
                "target": "gateway:10.0.0.1",
                "relation": "segment_gateway",
            },
            {
                "source": "segment:10.0.1.0/24",
                "target": "gateway:10.0.0.1",
                "relation": "segment_gateway",
            },
        ],
        "summary": {},
    }

    result = decorate_global_routing_topology(topology)
    gateway = next(node for node in result["nodes"] if node["id"] == "gateway:10.0.0.1")
    assert "router" in gateway["roles"]
    assert result["summary"]["routers"] == 1
    assert result["routing"]["routers"][0]["connected_segments"] == [
        "segment:10.0.0.0/24",
        "segment:10.0.1.0/24",
    ]
