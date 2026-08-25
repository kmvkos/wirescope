import backend.routers.topology as topology_router
from tests.helpers import http_request as request


def _fixture(audit_id: str, *, vlan: int):
    return {
        "audit": {
            "id": audit_id,
            "profile": "deep",
            "interface": "eth0",
            "status": "completed",
        },
        "nodes": [
            {
                "id": f"asset:{audit_id}",
                "kind": "asset",
                "label": "server-01",
                "mac": "00:11:22:33:44:55",
                "addresses": ["192.0.2.10"],
                "vlan_ids": [vlan],
                "roles": [],
            }
        ],
        "edges": [],
        "segments": [{"network": "192.0.2.0/24"}],
    }


def test_topology_compare_api_uses_current_path_and_against_baseline(api_context, monkeypatch):
    app, _service, _evidence, _environment = api_context
    documents = {
        "audit-old": _fixture("audit-old", vlan=10),
        "audit-new": _fixture("audit-new", vlan=20),
    }

    def fake_build_topology(_services, audit_id: str, **_kwargs):
        return documents[audit_id]

    monkeypatch.setattr(topology_router, "build_topology", fake_build_topology)
    response = request(
        app,
        "GET",
        "/api/v1/audits/audit-new/topology/compare?against=audit-old",
        as_role="viewer",
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["schema"] == "network-topology-diff"
    assert result["baseline"]["audit_id"] == "audit-old"
    assert result["current"]["audit_id"] == "audit-new"
    assert result["summary"]["nodes_changed"] == 1
    assert result["nodes"]["changed"][0]["changes"]["vlan_ids"] == {
        "before": [10],
        "after": [20],
    }


def test_topology_compare_api_rejects_same_audit(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(
        app,
        "GET",
        "/api/v1/audits/audit-same/topology/compare?against=audit-same",
        as_role="viewer",
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "same_topology"
