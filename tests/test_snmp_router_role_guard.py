from topology.snmp_role_guard import guard_snmp_router_roles


def _device(roles):
    return {
        "id": "asset:device",
        "kind": "network-device",
        "label": "device",
        "roles": roles,
        "provenance": ["credentialed-snmp-ip-mib"],
    }


def _interface(node_id, address):
    return {
        "id": node_id,
        "kind": "network-interface",
        "label": address,
        "roles": ["router-interface"],
        "addresses": [address],
        "parent_device_id": "asset:device",
    }


def test_single_management_prefix_does_not_turn_l2_switch_into_router():
    topology = {
        "routing": {"routers": []},
        "nodes": [
            _device(["network-device", "snmp-managed", "router"]),
            _interface("if:1", "192.0.2.2/24"),
        ],
    }
    result = guard_snmp_router_roles(topology)
    roles = result["nodes"][0]["roles"]
    assert "router" not in roles
    assert "router-candidate" not in roles


def test_two_distinct_connected_prefixes_are_observed_router_evidence():
    topology = {
        "routing": {"routers": []},
        "nodes": [
            _device(["network-device", "snmp-managed", "router"]),
            _interface("if:1", "192.0.2.1/24"),
            _interface("if:2", "10.20.0.1/24"),
        ],
    }
    result = guard_snmp_router_roles(topology)
    device = result["nodes"][0]
    assert "router" in device["roles"]
    assert device["routing_confidence"] == "observed"
    assert device["connected_segments"] == ["segment:10.20.0.0/24", "segment:192.0.2.0/24"]


def test_preexisting_confirmed_gateway_router_role_is_preserved():
    topology = {
        "routing": {"routers": [{"node_id": "asset:device"}]},
        "nodes": [
            _device(["network-device", "snmp-managed", "gateway", "router"]),
            _interface("if:1", "192.0.2.1/24"),
        ],
    }
    result = guard_snmp_router_roles(topology)
    roles = result["nodes"][0]["roles"]
    assert "gateway" in roles
    assert "router" in roles
