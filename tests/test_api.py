import asyncio

from httpx import ASGITransport, AsyncClient

import backend.app as backend_app


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


def test_passive_start_clamps_duration_and_creates_job(monkeypatch):
    captured = {}

    def fake_create_job(**kwargs):
        captured.update(kwargs)
        return "job-1"

    monkeypatch.setattr(backend_app, "create_job", fake_create_job)

    response = request(
        "POST",
        "/api/passive/start",
        params={"interface": "eth0", "duration": 999},
    )

    assert response.status_code == 200
    assert response.json() == {"job_id": "job-1", "status": "queued"}
    assert captured["job_type"] == "passive_discovery"
    assert captured["target"] == "eth0"
    assert captured["interface"] == "eth0"
    assert captured["duration"] == 300


def test_missing_job_returns_404(monkeypatch):
    monkeypatch.setattr(backend_app, "get_job", lambda _job_id: None)

    response = request("GET", "/api/jobs/missing")

    assert response.status_code == 404
    assert response.json() == {"detail": "Job not found"}


def test_root_serves_frontend():
    response = request("GET", "/")

    assert response.status_code == 200
    assert "WireScope" in response.text
