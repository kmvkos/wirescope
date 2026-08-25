from topology.builder import assemble_topology
from tests.helpers import http_request as request


def _sample_topology(*, overlay_interface="ens37"):
    return assemble_topology(
        audit={
            "id": "audit-deep",
            "profile": "deep",
            "interface": "ens37",
            "status": "completed",
            "scope": {"targets": ["10.0.0.0/24"]},
        },
        assets=[
            {
                "id": "gw",
                "state": "responsive",
                "mac": "00:11:22:33:44:01",
                "vendor": "Example Networks",
                "device_class_hint": "network-device-like",
                "os_name": "RouterOS",
                "addresses": ["10.0.0.1"],
                "names": ["gateway.local"],
            },
            {
                "id": "server",
                "state": "responsive",
                "mac": "00:11:22:33:44:10",
                "vendor": "Example",
                "device_class_hint": "server-like",
                "os_name": "Linux",
                "addresses": ["10.0.0.10"],
                "names": ["server01"],
            },
        ],
        services=[
            {
                "id": "svc-https",
                "asset_id": "server",
                "protocol": "tcp",
                "port": 443,
                "state": "open",
                "service_name": "https",
                "product": "nginx",
                "version": "1.26",
            }
        ],
        environment={
            "interfaces": [
                {"name": "ens37", "ipv4": ["10.0.0.50/24"], "ipv6": []}
            ],
            "default_route": {"gateway": "10.0.0.1", "interface": "ens37"},
        },
        passive={
            "tagged_vlan_ids": [20],
            "neighbors": [
                {
                    "protocol": "LLDP",
                    "name": "Switch-01",
                    "port_id": "Gi1/0/24",
                    "pvid": 20,
                }
            ],
            "stp": {
                "bridge_ids": ["8000.001122334455"],
                "root_bridge_ids": ["8000.001122334455"],
            },
            "dhcp": {
                "servers": ["10.0.0.1"],
                "routers": ["10.0.0.1"],
            },
        },
        confirmed_scope={
            "targets": ["10.0.0.0/24"],
            "route_context": {"gateway": "10.0.0.1"},
        },
        traffic_analysis={
            "job_id": "traffic-1",
            "audit_id": "capture-audit",
            "document": {
                "analyzer_version": 5,
                "source": {
                    "interface": overlay_interface,
                    "capture_job_id": "capture-1",
                },
                "summary": {"frame_count": 1200, "duration_seconds": 60},
                "communications_graph": {
                    "edges": [
                        {
                            "endpoint_a": "10.0.0.10",
                            "endpoint_b": "8.8.8.8",
                            "packets": 120,
                            "bytes": 45000,
                            "protocols": [{"name": "TLS/HTTPS", "frames": 100}],
                            "ports": [{"port": "tcp/443", "frames": 100}],
                        },
                        {
                            "endpoint_a": "10.0.0.10",
                            "endpoint_b": "224.0.0.251",
                            "packets": 5,
                            "bytes": 600,
                            "protocols": [{"name": "mDNS", "frames": 5}],
                            "ports": [{"port": "udp/5353", "frames": 5}],
                        },
                    ]
                },
            },
        },
    )


def test_topology_keeps_provenance_and_confidence_distinct():
    topology = _sample_topology()
    nodes = {item["id"]: item for item in topology["nodes"]}

    gateway = nodes["asset:gw"]
    assert "gateway" in gateway["roles"]
    assert gateway["confidence"] == "confirmed"

    lldp_edges = [edge for edge in topology["edges"] if edge["relation"] == "layer2_neighbor"]
    assert len(lldp_edges) == 1
    assert lldp_edges[0]["confidence"] == "confirmed"
    assert "lldp" in lldp_edges[0]["provenance"]

    traffic_edges = [edge for edge in topology["edges"] if edge["relation"] == "communication"]
    assert len(traffic_edges) == 2
    assert all(edge["confidence"] == "observed" for edge in traffic_edges)
    assert all("pcap" in edge["provenance"] for edge in traffic_edges)

    assert nodes["group:224.0.0.251"]["kind"] == "multicast-group"
    assert any(group["id"] == "vlan:20" for group in topology["groups"])
    subnet = next(group for group in topology["groups"] if group["id"] == "subnet:10.0.0.0/24")
    assert "asset:server" in subnet["members"]
    assert subnet["confidence"] == "inferred"


def test_topology_warns_when_operator_overlays_another_interface():
    topology = _sample_topology(overlay_interface="ens99")
    assert topology["overlay"]["interface"] == "ens99"
    assert any("ens99" in warning and "ens37" in warning for warning in topology["warnings"])


def test_topology_api_returns_segment_aware_base_map_for_empty_audit(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={"targets": ["192.0.2.0/24"]},
        actor="auditor",
    )

    response = request(app, "GET", f"/api/v1/audits/{audit.id}/topology", as_role="viewer")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["schema"] == "network-topology"
    assert data["schema_version"] == 2
    assert data["model"] == "segment-aware"
    assert data["audit"]["id"] == audit.id
    assert any(node["kind"] == "wirescope" for node in data["nodes"])
    assert "layers" in data


def test_global_topology_api_exists(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/api/v1/topology/global", as_role="viewer")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["schema"] == "network-topology-global"
    assert data["model"] == "cross-audit-segments"


def test_topology_api_rejects_unknown_overlay(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    response = request(
        app,
        "GET",
        f"/api/v1/audits/{audit.id}/topology?traffic_analysis_job_id=missing",
        as_role="viewer",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "topology_source_invalid"
