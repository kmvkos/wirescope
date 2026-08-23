import asyncio
from dataclasses import replace
from types import SimpleNamespace

from httpx import ASGITransport, AsyncClient
import pytest

from backend.app import create_app
from engine.interfaces import (
    InterfaceInfo,
    InterfaceValidationCode,
    InterfaceValidationError,
)
from engine.routes import ResolvedScope, TargetRoute
from jobs.models import RetentionClass
from storage.evidence import EvidenceStore


def request(app, method, path, **kwargs):
    async def send():
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


class RouteStub:
    def resolve(self, interface_name, scope):
        return ResolvedScope(
            interface=interface_name,
            interface_state="UP",
            vlan_subinterface="." in interface_name,
            routes=[
                TargetRoute(
                    target=target.value,
                    representative_address=target.value.split("/", 1)[0],
                    family=target.family,
                    interface=interface_name,
                    source_address=(
                        "192.0.2.10"
                        if target.family == 4
                        else "2001:db8::10"
                    ),
                    gateway=None,
                    directly_connected=True,
                )
                for target in scope.targets
            ],
        )


class InterfaceStub:
    def __init__(self):
        self.interface = InterfaceInfo(
            name="eth0",
            state="UP",
            allowed=True,
        )

    def validate(self, name):
        if name != self.interface.name:
            raise InterfaceValidationError(
                InterfaceValidationCode.UNKNOWN_INTERFACE,
                f"Unknown network interface: {name}",
            )
        return self.interface

    def discover(self):
        return SimpleNamespace(interfaces=[self.interface])


@pytest.fixture
def api_context(
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    settings = replace(
        durable_settings,
        dumpcap_binary="/bin/true",
        tshark_binary="/bin/true",
        nmap_binary="/bin/true",
    )
    environment = {
        "hostname": "wirescope-test",
        "interfaces": [],
        "default_route": None,
        "routes": [],
        "dns": [],
    }
    app = create_app(
        settings=settings,
        database=database,
        job_service=job_service,
        evidence_store=evidence_store,
        interface_service=InterfaceStub(),
        route_resolver=RouteStub(),
        environment_provider=lambda: environment,
    )
    return app, job_service, evidence_store, environment


def create_audit(app):
    return request(
        app,
        "POST",
        "/api/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"site": "lab"},
        },
    )


def test_health_and_environment_endpoints(api_context):
    app, _service, _evidence, environment = api_context

    health = request(app, "GET", "/api/health")
    status = request(app, "GET", "/api/status")
    response = request(app, "GET", "/api/environment")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert status.json() == health.json()
    assert response.json() == environment


def test_create_audit_persists_environment_reference(api_context):
    app, service, _evidence, _environment = api_context

    response = create_audit(app)

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "created"
    assert payload["environment_snapshot_reference"]
    assert service.get_audit(payload["id"]).scope == {"site": "lab"}


def test_enqueue_passive_job_and_paginated_listing(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={"duration_seconds": 45, "priority": 5},
    )

    assert response.status_code == 202
    job_id = response.json()["job_id"]
    persisted = service.get_job(job_id)
    assert persisted.parameters["duration_seconds"] == 45
    assert persisted.resource_key == "interface:eth0"
    listing = request(
        app,
        "GET",
        "/api/jobs",
        params={"limit": 1, "offset": 0, "status": "queued"},
    )
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["result_available"] is False
    audit_jobs = request(app, "GET", f"/api/audits/{audit_id}/jobs")
    assert audit_jobs.json()["items"][0]["id"] == job_id


def test_passive_job_rejects_out_of_range_duration(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={"duration_seconds": 999},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_duration"


def test_create_audit_rejects_unknown_interface(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(
        app,
        "POST",
        "/api/audits",
        json={"profile": "passive", "interface": "missing0"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_interface"


def test_create_audit_rejects_oversized_scope(api_context):
    app, _service, _evidence, _environment = api_context

    response = request(
        app,
        "POST",
        "/api/audits",
        json={
            "profile": "passive",
            "interface": "eth0",
            "scope": {"note": "x" * 20_000},
        },
    )

    assert response.status_code == 422


def test_queued_job_cancellation_endpoint(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    job_id = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={},
    ).json()["job_id"]

    response = request(app, "POST", f"/api/jobs/{job_id}/cancel")

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    events = request(app, "GET", f"/api/jobs/{job_id}/events")
    assert events.json()["total"] == 2


def test_separate_job_result_endpoint(api_context):
    app, service, evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]
    job_id = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/passive",
        json={},
    ).json()["job_id"]
    service.claim_next("api-test-worker")
    document = {
        "schema": "passive-result",
        "schema_version": 1,
        "result": {"interface": "eth0"},
    }
    artifact = evidence.put_json(
        audit_id=audit_id,
        job_id=job_id,
        artifact_type="passive_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="passive-result",
        schema_version=1,
    )
    service.complete_job(job_id, result_reference=artifact.id)

    status = request(app, "GET", f"/api/jobs/{job_id}")
    result = request(app, "GET", f"/api/jobs/{job_id}/result")

    assert "result" not in status.json()
    assert status.json()["result_available"] is True
    assert result.json() == document


def test_readiness_distinguishes_missing_and_live_worker(api_context):
    app, service, _evidence, _environment = api_context

    unavailable = request(app, "GET", "/api/ready")
    service.register_worker("ready-worker")
    service.heartbeat_worker("ready-worker", status="idle")
    available = request(app, "GET", "/api/ready")

    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["worker"] is False
    assert available.status_code == 200
    assert available.json()["status"] == "ready"


def test_interfaces_missing_entities_and_removed_legacy_routes(api_context):
    app, _service, _evidence, _environment = api_context

    interfaces = request(app, "GET", "/api/interfaces")
    missing = request(app, "GET", "/api/jobs/missing")
    legacy = request(app, "POST", "/api/passive/start", json={})

    assert interfaces.json()["interfaces"][0]["name"] == "eth0"
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "not_found"
    assert legacy.status_code == 404


def test_root_serves_frontend(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/")

    assert response.status_code == 200
    assert "WireScope" in response.text


def test_enqueue_discovery_confirms_scope_and_lists_empty_inventory(api_context):
    app, service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    response = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={
            "interface": "eth0",
            "scope": ["192.0.2.0/24"],
            "profile": "standard",
        },
    )

    assert response.status_code == 202
    job = service.get_job(response.json()["job_id"])
    assert job.type == "active_discovery"
    assert job.parameters["scope"] == ["192.0.2.0/24"]
    assert job.parameters["confirmed_scope_id"]
    assert job.resource_key == "interface:eth0"
    assert job.resource_group == "active_discovery"
    status = request(app, "GET", f"/api/jobs/{job.id}")
    assert "assets" not in status.json()
    assets = request(app, "GET", f"/api/audits/{audit_id}/assets")
    services = request(
        app,
        "GET",
        f"/api/audits/{audit_id}/services",
        params={"port": 443},
    )
    summary = request(app, "GET", f"/api/audits/{audit_id}/inventory")
    assert assets.status_code == 200
    assert assets.json()["total"] == 0
    assert services.json()["total"] == 0
    assert summary.json()["assets"] == 0


def test_discovery_rejects_unspecified_and_oversize_scope(api_context):
    app, _service, _evidence, _environment = api_context
    audit_id = create_audit(app).json()["id"]

    unspecified = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["0.0.0.0/0"], "profile": "discovery"},
    )
    ipv6 = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["::/0"], "profile": "standard"},
    )
    oversized = request(
        app,
        "POST",
        f"/api/audits/{audit_id}/discovery",
        json={"interface": "eth0", "scope": ["10.0.0.0/8"], "profile": "standard"},
    )
    assert unspecified.status_code == 422
    assert unspecified.json()["detail"]["code"] == "prohibited_target"
    assert ipv6.json()["detail"]["code"] == "prohibited_target"
    assert oversized.json()["detail"]["code"] == "scope_limit_exceeded"
