from types import SimpleNamespace

from appliance import cli
from appliance.wait import health_url, wait_ready


class _HealthyResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_health_url_normalizes_public_bind_to_loopback_and_accepts_tls():
    assert health_url("0.0.0.0", 8000, tls=False) == "http://127.0.0.1:8000/api/health"
    assert health_url("0.0.0.0", 8443, tls=True) == "https://127.0.0.1:8443/api/health"


def test_wait_ready_returns_true_for_healthy_endpoint(monkeypatch):
    monkeypatch.setattr(
        "appliance.wait.urllib.request.urlopen",
        lambda *args, **kwargs: _HealthyResponse(),
    )
    assert wait_ready(url="http://127.0.0.1:8000/api/health", timeout_seconds=0.1) is True


def test_appliance_wait_ready_cli_returns_zero_when_api_is_healthy(monkeypatch):
    monkeypatch.setattr(
        cli,
        "_runtime_settings",
        lambda: SimpleNamespace(
            bind_host="0.0.0.0",
            bind_port=8000,
            tls_enabled=False,
        ),
    )
    monkeypatch.setattr(cli, "wait_ready", lambda *args, **kwargs: True)

    args = SimpleNamespace(url="", timeout=1.0)
    assert cli.cmd_wait_ready(args) == 0
