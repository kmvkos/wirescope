from topology.completeness import decorate_completeness
from topology.presentation import decorate_presentation


def _base_topology():
    return {
        "schema": "network-topology",
        "schema_version": 2,
        "audit": {"interface": "ens37"},
        "segments": [
            {
                "id": "segment:10.11.11.0/24",
                "network": "10.11.11.0/24",
                "members": [
                    "wirescope:ens37",
                    "asset:router",
                    "asset:host",
                    "endpoint:10.11.11.255",
                ],
            }
        ],
        "nodes": [
            {
                "id": "wirescope:ens37",
                "kind": "wirescope",
                "label": "WireScope · ens37",
                "roles": ["sensor"],
                "addresses": ["10.11.11.124/24", "fe80::124/64"],
                "provenance": ["environment"],
                "confidence": "confirmed",
            },
            {
                "id": "asset:router",
                "kind": "asset",
                "label": "10.11.11.11",
                "roles": ["gateway"],
                "addresses": ["10.11.11.11"],
                "names": [],
                "state": "responsive",
                "provenance": ["inventory", "confirmed-scope-route"],
                "confidence": "confirmed",
            },
            {
                "id": "asset:host",
                "kind": "asset",
                "label": "host.local",
                "roles": [],
                "addresses": ["10.11.11.82", "fe80::82"],
                "names": ["host.local"],
                "state": "responsive",
                "services": [{"protocol": "tcp", "port": 443}],
                "provenance": ["inventory"],
                "confidence": "confirmed",
            },
            {
                "id": "endpoint:10.11.11.255",
                "kind": "endpoint",
                "label": "10.11.11.255",
                "roles": [],
                "addresses": ["10.11.11.255"],
                "provenance": ["pcap"],
                "confidence": "observed",
            },
            {
                "id": "endpoint:fe80::dead",
                "kind": "endpoint",
                "label": "fe80::dead",
                "roles": [],
                "addresses": ["fe80::dead"],
                "provenance": ["pcap"],
                "confidence": "observed",
            },
            {
                "id": "endpoint:5.188.18.125",
                "kind": "endpoint",
                "label": "5.188.18.125",
                "roles": [],
                "addresses": ["5.188.18.125"],
                "provenance": ["pcap"],
                "confidence": "observed",
            },
            {
                "id": "neighbor:lldp:netcraze",
                "kind": "network-device",
                "label": "Netcraze-7032",
                "roles": ["network-neighbor"],
                "addresses": [],
                "provenance": ["lldp"],
                "confidence": "confirmed",
            },
        ],
        "edges": [
            {
                "id": "edge:l2",
                "source": "wirescope:ens37",
                "target": "neighbor:lldp:netcraze",
                "relation": "layer2_neighbor",
                "layer": "l2",
                "confidence": "confirmed",
                "provenance": ["lldp"],
            },
            {
                "id": "edge:gw",
                "source": "wirescope:ens37",
                "target": "asset:router",
                "relation": "segment_gateway",
                "layer": "l3",
                "confidence": "confirmed",
                "provenance": ["confirmed-scope-route"],
            },
            {
                "id": "edge:traffic",
                "source": "asset:host",
                "target": "endpoint:5.188.18.125",
                "relation": "communication",
                "layer": "traffic",
                "confidence": "observed",
                "provenance": ["pcap"],
                "packets": 295,
            },
            {
                "id": "edge:broadcast",
                "source": "asset:host",
                "target": "endpoint:10.11.11.255",
                "relation": "communication",
                "layer": "traffic",
                "confidence": "observed",
                "provenance": ["pcap"],
            },
        ],
        "overlay": {"traffic_analysis_job_id": "pcap-1", "interface": "ens37"},
        "warnings": [],
    }


def test_structural_projection_separates_pcap_and_hides_directed_broadcast_and_link_local_noise():
    topology = decorate_presentation(_base_topology())
    presentation = topology["presentation"]
    structural = presentation["views"]["structural"]
    traffic = presentation["views"]["traffic"]

    assert structural["edge_ids"] == ["edge:gw", "edge:l2"]
    assert "endpoint:5.188.18.125" not in structural["node_ids"]
    assert "endpoint:10.11.11.255" not in structural["node_ids"]
    assert "endpoint:fe80::dead" not in structural["node_ids"]
    assert "edge:traffic" in traffic["edge_ids"]
    assert "endpoint:5.188.18.125" in traffic["node_ids"]
    assert presentation["suppressed"]["broadcast_multicast_node_ids"] == ["endpoint:10.11.11.255"]
    assert presentation["suppressed"]["unidentified_link_local_count"] == 1
    assert presentation["labels"]["asset:host"] == "host.local"


def test_completeness_states_exactly_what_current_evidence_can_claim():
    topology = decorate_completeness(_base_topology())
    coverage = topology["coverage"]

    assert coverage["domains"]["inventory"]["status"] == "sufficient"
    assert coverage["domains"]["l3"]["status"] == "sufficient"
    assert coverage["domains"]["l2"]["status"] == "partial"
    assert coverage["domains"]["traffic"]["status"] == "sufficient"
    assert coverage["domains"]["vlan"]["status"] == "missing"
    assert coverage["claims"]["gateway"] is True
    assert coverage["claims"]["direct_l2_adjacency"] is True
    assert coverage["claims"]["physical_switch_port"] is False
    assert coverage["claims"]["wifi_association"] is False
    assert coverage["claims"]["hypervisor_placement"] is False


def test_missing_interface_gateway_is_reported_as_partial_not_invented():
    topology = _base_topology()
    topology["edges"] = [edge for edge in topology["edges"] if edge["id"] != "edge:gw"]
    topology["nodes"][1]["roles"] = []
    topology = decorate_completeness(topology)

    assert topology["coverage"]["domains"]["l3"]["status"] == "partial"
    assert topology["coverage"]["claims"]["gateway"] is False
    assert any("gateway evidence" in item for item in topology["coverage"]["recommendations"])
