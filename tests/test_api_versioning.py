from tests.helpers import http_request as request


def test_v1_is_canonical_and_legacy_routes_remain_compatible(api_context):
    app, service, _evidence, environment = api_context

    legacy_health = request(app, "GET", "/api/health", auth=False)
    v1_health = request(app, "GET", "/api/v1/health", auth=False)
    assert v1_health.status_code == 200
    assert v1_health.json() == legacy_health.json()

    unauthorized = request(
        app,
        "GET",
        "/api/v1/environment",
        auth=False,
    )
    assert unauthorized.status_code == 401

    v1_environment = request(app, "GET", "/api/v1/environment")
    assert v1_environment.status_code == 200
    assert v1_environment.json() == environment

    created = request(
        app,
        "POST",
        "/api/v1/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"site": "v1-test"},
        },
    )
    assert created.status_code == 201
    audit_id = created.json()["id"]
    assert service.get_audit(audit_id).scope == {"site": "v1-test"}

    legacy_read = request(app, "GET", f"/api/audits/{audit_id}")
    assert legacy_read.status_code == 200
    assert legacy_read.json()["id"] == audit_id

    schema = request(app, "GET", "/openapi.json", auth=False)
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert "/api/v1/health" in paths
    assert "/api/v1/audits" in paths
    assert "/api/health" not in paths
    assert "/api/audits" not in paths
