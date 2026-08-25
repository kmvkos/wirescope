from collections import Counter

from topology.ssh_management import _decorate_document


def _base_topology():
    return {
        "nodes": [
            {
                "id": "router",
                "kind": "asset",
                "label": "router",
                "addresses": ["10.11.11.11"],
                "names": [],
                "mac": "00:11:22:33:44:55",
                "roles": ["router"],
                "provenance": ["inventory"],
            },
            {
                "id": "client-access",
                "kind": "asset",
                "label": "access-client",
                "addresses": ["10.11.11.20"],
                "names": [],
                "mac": "aa:bb:cc:dd:ee:01",
                "roles": [],
                "provenance": ["inventory"],
            },
            {
                "id": "client-trunk",
                "kind": "asset",
                "label": "trunk-client",
                "addresses": ["10.11.11.21"],
                "names": [],
                "mac": "aa:bb:cc:dd:ee:02",
                "roles": [],
                "provenance": ["inventory"],
            },
        ],
        "edges": [],
        "segments": [],
        "warnings": [],
        "summary": {},
    }


def _document(*, exact_trunk_vlan=None):
    return {
        "schema": "ssh-topology-result",
        "schema_version": 1,
        "target": "10.11.11.11",
        "interfaces": [],
        "neighbors": [],
        "routes": [],
        "wifi_associations": [],
        "warnings": [],
        "vlans": [
            {
                "port": "eth1",
                "pvid": 10,
                "tagged_vlans": [],
                "untagged_vlans": [10],
            },
            {
                "port": "eth2",
                "pvid": 10,
                "tagged_vlans": [20, 30],
                "untagged_vlans": [10],
            },
        ],
        "fdb": [
            {
                "mac": "aa:bb:cc:dd:ee:01",
                "port": "eth1",
                "vlan_id": None,
            },
            {
                "mac": "aa:bb:cc:dd:ee:02",
                "port": "eth2",
                "vlan_id": exact_trunk_vlan,
            },
        ],
    }


def _edge(topology, target):
    return next(
        edge
        for edge in topology["edges"]
        if edge.get("mapping_type") == "switch_port" and edge.get("target") == target
    )


def test_access_port_can_supply_unambiguous_vlan_but_trunk_cannot():
    topology = _base_topology()

    _decorate_document(topology, _document(), "artifact-1", Counter())

    access = next(node for node in topology["nodes"] if node["id"] == "client-access")
    trunk = next(node for node in topology["nodes"] if node["id"] == "client-trunk")
    access_edge = _edge(topology, "client-access")
    trunk_edge = _edge(topology, "client-trunk")

    assert access["vlan_ids"] == [10]
    assert access_edge["port_mode"] == "access"
    assert access_edge["vlan_ids"] == [10]
    assert access_edge["vlan_source"] == "unambiguous_access_port"

    assert trunk.get("vlan_ids", []) == []
    assert trunk_edge["port_mode"] == "trunk"
    assert trunk_edge["pvid"] == 10
    assert trunk_edge["tagged_vlans"] == [20, 30]
    assert trunk_edge["untagged_vlans"] == [10]
    assert trunk_edge["vlan_ids"] == []
    assert trunk_edge["vlan_source"] is None


def test_exact_fdb_vlan_is_allowed_even_on_trunk_port():
    topology = _base_topology()

    _decorate_document(topology, _document(exact_trunk_vlan=20), "artifact-2", Counter())

    trunk = next(node for node in topology["nodes"] if node["id"] == "client-trunk")
    trunk_edge = _edge(topology, "client-trunk")

    assert trunk["vlan_ids"] == [20]
    assert trunk_edge["port_mode"] == "trunk"
    assert trunk_edge["vlan_ids"] == [20]
    assert trunk_edge["vlan_source"] == "fdb"
