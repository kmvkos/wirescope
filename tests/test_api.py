import asyncio
from types import SimpleNamespace

from httpx import ASGITransport, AsyncClient

import backend.app as backend_app
from engine.interfaces import (
    InterfaceInfo,
    InterfaceValidationCode,
    InterfaceValidationError,
)


def request(method, path, **kwargs):
    async def send():
        transport = ASGITransport(app=backend_app.app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_status_endpoint():
    response = request("GET", "/api/status")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "product": "WireScope",
        "version": "0.1.0",
    }


def test_environment_endpoint_uses_engine(monkeypatch):
    expected = {
        "hostname": "wirescope-test",
        "interfaces": [],
        "default_route": None,
        "routes": [],
        "dns": [],
    }
    monkeypatch.setattr(backend_app, "get_environment", lambda: expected)

    response = request("GET", "/api/environment")

    assert response.status_code == 200
    assert response.json() == expected


def test_passive_start_validates_and_creates_job(monkeypatch):
    captured = {}

    def fake_create_job(**kwargs):
        captured.update(kwargs)
        return "job-1"

    monkeypatch.setattr(backend_app, "create_job", fake_create_job)
    monkeypatch.setattr(
        backend_app.interface_service,
        "validate",
        lambda name: InterfaceInfo(name=name, state="UP", allowed=True),
    )

    response = request(
        "POST",
        "/api/passive/start",
        json={"interface": "eth0", "duration_seconds": 45},
    )

    assert response.status_code == 200
    assert response.json() == {"job_id": "job-1", "status": "queued"}
    assert captured["job_type"] == "passive_discovery"
    assert captured["target"] == "eth0"
    assert captured["interface"] == "eth0"
    assert captured["duration"] == 45


def test_passive_start_rejects_out_of_range_duration():
    response = request(
        "POST",
        "/api/passive/start",
        json={"interface": "eth0", "duration_seconds": 999},
    )

    assert response.status_code == 422


def test_passive_start_rejects_unknown_interface(monkeypatch):
    def reject(_name):
        raise InterfaceValidationError(
            InterfaceValidationCode.UNKNOWN_INTERFACE,
            "Unknown network interface: missing0",
        )

    monkeypatch.setattr(
        backend_app.interface_service,
        "validate",
        reject,
    )

    response = request(
        "POST",
        "/api/passive/start",
        json={"interface": "missing0", "duration_seconds": 30},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_interface"


def test_legacy_synchronous_passive_endpoint_is_removed():
    response = request("GET", "/api/passive/eth0")

    assert response.status_code == 404


def test_interfaces_endpoint_returns_policy_metadata(monkeypatch):
    interface = InterfaceInfo(
        name="eth0",
        state="UP",
        allowed=True,
    )
    monkeypatch.setattr(
        backend_app.interface_service,
        "discover",
        lambda: SimpleNamespace(interfaces=[interface]),
    )

    response = request("GET", "/api/interfaces")

    assert response.status_code == 200
    assert response.json()["interfaces"][0]["name"] == "eth0"
    assert response.json()["interfaces"][0]["allowed"] is True


def test_missing_job_returns_404(monkeypatch):
    monkeypatch.setattr(backend_app, "get_job", lambda _job_id: None)

    response = request("GET", "/api/jobs/missing")

    assert response.status_code == 404
    assert response.json() == {"detail": "Job not found"}


def test_root_serves_frontend():
    response = request("GET", "/")

    assert response.status_code == 200
    assert "WireScope" in response.text
