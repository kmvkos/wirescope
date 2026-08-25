import inspect

from appliance.wait import health_url, wait_ready


def test_wait_ready_accepts_cli_positional_url_contract():
    signature = inspect.signature(wait_ready)
    url = signature.parameters["url"]
    assert url.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_health_url_maps_public_listener_to_loopback():
    assert health_url("0.0.0.0", 8000, tls=False) == "http://127.0.0.1:8000/api/health"
    assert health_url("0.0.0.0", 8443, tls=True) == "https://127.0.0.1:8443/api/health"
