from engine.active_profiles import profile_for
from engine.routes import ResolvedScope, TargetRoute
from engine.scope import ActiveProfile, ScopeValidator
from providers.nmap import NmapProvider
from providers.route_trace import (
    _parse_tracepath,
    _parse_traceroute,
    representative_routed_targets,
)
from tests.helpers import RecordingRunner
from topology.upstream import _correct_routed_gateway, _decorate_trace, _route_contexts


def _resolved(*, direct: bool) -> ResolvedScope:
    return ResolvedScope(
        interface="eth0",
        interface_state="UP",
        vlan_subinterface=False,
        routes=[
            TargetRoute(
                target="198.51.100.0/24",
                representative_address="198.51.100.1",
                family=4,
                interface="eth0",
                source_address="192.0.2.10",
                gateway=None if direct else "192.0.2.1",
                directly_connected=direct,
            )
        ],
    )


def test_standard_and_deep_record_only_routed_targets_for_trace(durable_settings, tmp_path):
    provider = NmapProvider(
        runner=RecordingRunner(),
        settings=durable_settings,
        privileged=False,
    )
    for profile_name in (ActiveProfile.STANDARD, ActiveProfile.DEEP):
        scope = ScopeValidator(durable_settings).validate(
            ["198.51.100.0/24"], profile_name
        )
        plan = provider.build_host_discovery(
            scope=scope,
            resolved=_resolved(direct=False),
            profile=profile_for(profile_name, durable_settings),
            xml_path=tmp_path / f"{profile_name.value}.xml",
            target_file=tmp_path / f"{profile_name.value}.targets",
        )
        assert len(plan.route_trace_routes) == 1
        assert plan.route_trace_routes[0]["target"] == "198.51.100.0/24"
        assert plan.route_trace_routes[0]["source_address"] == "192.0.2.10"
        assert plan.route_trace_routes[0]["gateway"] == "192.0.2.1"

    direct_scope = ScopeValidator(durable_settings).validate(
        ["198.51.100.0/24"], ActiveProfile.DEEP
    )
    direct_plan = provider.build_host_discovery(
        scope=direct_scope,
        resolved=_resolved(direct=True),
        profile=profile_for(ActiveProfile.DEEP, durable_settings),
        xml_path=tmp_path / "direct.xml",
        target_file=tmp_path / "direct.targets",
    )
    assert direct_plan.route_trace_routes == []


def test_representative_trace_target_is_live_and_inside_authorized_routed_scope():
    selected = representative_routed_targets(
        live_addresses=["192.0.2.55", "198.51.100.20", "198.51.100.30"],
        resolved_routes=[
            {
                "target": "198.51.100.0/24",
                "family": 4,
                "source_address": "192.0.2.10",
                "gateway": "192.0.2.1",
                "directly_connected": False,
            },
            {
                "target": "192.0.2.0/24",
                "family": 4,
                "source_address": "192.0.2.10",
                "gateway": None,
                "directly_connected": True,
            },
        ],
    )
    assert [
        (item.address, item.scope_target, item.source_address, item.gateway)
        for item in selected
    ] == [
        ("198.51.100.20", "198.51.100.0/24", "192.0.2.10", "192.0.2.1")
    ]


def test_route_context_survives_even_when_trace_tool_is_unavailable():
    contexts = _route_contexts(
        {
            "targets": [
                {
                    "target": "198.51.100.20",
                    "scope_target": "198.51.100.0/24",
                    "source_address": "192.0.2.10",
                    "gateway": "192.0.2.1",
                }
            ],
            "traces": [],
        }
    )
    assert contexts == [
        {
            "target": "198.51.100.20",
            "scope_target": "198.51.100.0/24",
            "source_address": "192.0.2.10",
            "gateway": "192.0.2.1",
        }
    ]


def test_traceroute_and_tracepath_parsers_keep_unknown_hops_explicit():
    traceroute = _parse_traceroute(
        "traceroute to 198.51.100.20, 16 hops max\n"
        " 1  192.0.2.1  0.351 ms\n"
        " 2  *\n"
        " 3  198.51.100.20  4.200 ms\n"
    )
    assert traceroute == [
        {"ttl": 1, "address": "192.0.2.1", "rtt_ms": 0.351, "responded": True},
        {"ttl": 2, "address": None, "rtt_ms": None, "responded": False},
        {"ttl": 3, "address": "198.51.100.20", "rtt_ms": 4.2, "responded": True},
    ]

    tracepath = _parse_tracepath(
        " 1?: [LOCALHOST] pmtu 1500\n"
        " 1:  192.0.2.1  0.210ms\n"
        " 2:  no reply\n"
        " 3:  198.51.100.20  4.800ms reached\n"
    )
    assert [item["address"] for item in tracepath] == [
        "192.0.2.1",
        None,
        "198.51.100.20",
    ]


def _routed_topology():
    return {
        "audit": {"id": "audit-routed", "interface": "eth0"},
        "segments": [
            {
                "id": "segment:198.51.100.0/24",
                "network": "198.51.100.0/24",
                "gateways": ["192.0.2.1"],
                "provenance": ["confirmed-scope-route"],
            }
        ],
        "nodes": [
            {
                "id": "wirescope:eth0",
                "kind": "wirescope",
                "label": "WireScope · eth0",
                "roles": ["sensor"],
                "addresses": ["192.0.2.10/24"],
                "provenance": ["environment"],
                "confidence": "confirmed",
            },
            {
                "id": "segment:198.51.100.0/24",
                "kind": "segment",
                "roles": ["subnet"],
                "addresses": [],
            },
            {
                "id": "asset:gateway",
                "kind": "asset",
                "label": "router01",
                "roles": ["gateway", "router"],
                "addresses": ["192.0.2.1"],
                "connected_segments": ["segment:198.51.100.0/24"],
                "provenance": ["confirmed-scope-route"],
            },
            {
                "id": "asset:target",
                "kind": "asset",
                "label": "server20",
                "roles": [],
                "addresses": ["198.51.100.20"],
            },
        ],
        "edges": [
            {
                "id": "wrong-remote-segment-gw",
                "source": "segment:198.51.100.0/24",
                "target": "asset:gateway",
                "relation": "segment_gateway",
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            }
        ],
        "routing": {
            "routers": [
                {
                    "node_id": "asset:gateway",
                    "connected_segments": ["segment:198.51.100.0/24"],
                    "confidence": "confirmed",
                }
            ],
            "router_candidates": [],
        },
        "summary": {},
    }


def test_routed_next_hop_is_moved_from_remote_target_to_local_source_segment():
    topology = _routed_topology()
    context = {
        "target": "198.51.100.20",
        "scope_target": "198.51.100.0/24",
        "source_address": "192.0.2.10",
        "gateway": "192.0.2.1",
    }
    _correct_routed_gateway(topology, context)

    segment_ids = {segment["id"] for segment in topology["segments"]}
    assert "segment:192.0.2.0/24" in segment_ids
    target_segment = next(
        segment for segment in topology["segments"]
        if segment["id"] == "segment:198.51.100.0/24"
    )
    source_segment = next(
        segment for segment in topology["segments"]
        if segment["id"] == "segment:192.0.2.0/24"
    )
    assert target_segment["gateways"] == []
    assert target_segment["route_via"] == "192.0.2.1"
    assert source_segment["gateways"] == ["192.0.2.1"]

    gateway_edges = [edge for edge in topology["edges"] if edge["relation"] == "segment_gateway"]
    assert len(gateway_edges) == 1
    assert gateway_edges[0]["source"] == "segment:192.0.2.0/24"
    assert gateway_edges[0]["target"] == "asset:gateway"

    gateway = next(node for node in topology["nodes"] if node["id"] == "asset:gateway")
    assert gateway["connected_segments"] == ["segment:192.0.2.0/24"]


def test_upstream_topology_uses_source_gateway_preserves_gap_and_reaches_target_segment():
    topology = _routed_topology()
    trace = {
        "target": "198.51.100.20",
        "scope_target": "198.51.100.0/24",
        "source_address": "192.0.2.10",
        "gateway": "192.0.2.1",
        "status": "completed",
        "reached_target": True,
        "hops": [
            {"ttl": 1, "address": "192.0.2.1", "rtt_ms": 0.4, "responded": True},
            {"ttl": 2, "address": None, "rtt_ms": None, "responded": False},
            {"ttl": 3, "address": "198.51.100.20", "rtt_ms": 4.2, "responded": True},
        ],
    }
    _correct_routed_gateway(topology, trace)
    _decorate_trace(
        topology,
        trace,
        artifact_id="trace-artifact",
        trace_index=0,
        tool="traceroute",
    )

    gateway_edges = [edge for edge in topology["edges"] if edge["relation"] == "segment_gateway"]
    assert len(gateway_edges) == 1
    assert gateway_edges[0]["source"] == "segment:192.0.2.0/24"

    route_edges = [edge for edge in topology["edges"] if edge["relation"] == "route_hop"]
    assert len(route_edges) == 2
    assert route_edges[0]["source"] == "asset:gateway"
    assert route_edges[0]["target"].startswith("route-gap:")
    assert route_edges[1]["target"] == "asset:target"
    assert any(node["kind"] == "route-gap" for node in topology["nodes"])

    target_edges = [edge for edge in topology["edges"] if edge["relation"] == "route_target"]
    assert len(target_edges) == 1
    assert target_edges[0]["source"] == "asset:target"
    assert target_edges[0]["target"] == "segment:198.51.100.0/24"


def test_unreached_trace_does_not_invent_connection_to_target_segment():
    topology = _routed_topology()
    trace = {
        "target": "198.51.100.20",
        "scope_target": "198.51.100.0/24",
        "source_address": "192.0.2.10",
        "gateway": "192.0.2.1",
        "status": "completed",
        "reached_target": False,
        "hops": [
            {"ttl": 1, "address": "192.0.2.1", "rtt_ms": 0.4, "responded": True},
            {"ttl": 2, "address": None, "rtt_ms": None, "responded": False},
        ],
    }
    _correct_routed_gateway(topology, trace)
    _decorate_trace(
        topology,
        trace,
        artifact_id="trace-artifact",
        trace_index=1,
        tool="traceroute",
    )
    assert not any(edge["relation"] == "route_target" for edge in topology["edges"])
