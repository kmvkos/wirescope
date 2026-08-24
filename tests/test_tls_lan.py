from pathlib import Path

from appliance.paths import InstallPaths, production_env_text
from appliance.tls import lan_warnings, self_signed_argv, validate_tls_settings
from appliance.wait import health_url
from backend.serve import uvicorn_run_kwargs
from config.settings import get_settings
from tests.helpers import http_request


def test_health_url_uses_https_when_tls_env_is_set(monkeypatch):
    monkeypatch.setenv("WIRESCOPE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("WIRESCOPE_BIND_PORT", "8443")
    monkeypatch.setenv("WIRESCOPE_TLS_CERTFILE", "/etc/wirescope/tls/cert.pem")
    monkeypatch.setenv("WIRESCOPE_TLS_KEYFILE", "/etc/wirescope/tls/key.pem")
    assert health_url() == "https://127.0.0.1:8443/api/health"


def test_health_url_defaults_to_loopback_http(monkeypatch):
    monkeypatch.delenv("WIRESCOPE_TLS_CERTFILE", raising=False)
    monkeypatch.delenv("WIRESCOPE_TLS_KEYFILE", raising=False)
    monkeypatch.delenv("WIRESCOPE_BIND_HOST", raising=False)
    monkeypatch.delenv("WIRESCOPE_BIND_PORT", raising=False)
    assert health_url() == "http://127.0.0.1:8000/api/health"


def test_settings_enable_secure_cookie_for_trust_proxy(monkeypatch):
    monkeypatch.setenv("WIRESCOPE_TRUST_PROXY", "true")
    monkeypatch.delenv("WIRESCOPE_SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("WIRESCOPE_TLS_CERTFILE", raising=False)
    monkeypatch.delenv("WIRESCOPE_TLS_KEYFILE", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.trust_proxy is True
    assert settings.session_cookie_secure is True
    get_settings.cache_clear()


def test_settings_reject_partial_tls_pair(monkeypatch):
    monkeypatch.setenv("WIRESCOPE_TLS_CERTFILE", "/tmp/cert.pem")
    monkeypatch.delenv("WIRESCOPE_TLS_KEYFILE", raising=False)
    get_settings.cache_clear()
    try:
        get_settings()
    except ValueError as exc:
        assert "together" in str(exc)
    else:
        raise AssertionError("partial TLS settings must fail")
    get_settings.cache_clear()


def test_uvicorn_kwargs_keep_backend_unprivileged(monkeypatch):
    monkeypatch.setenv("WIRESCOPE_TRUST_PROXY", "true")
    monkeypatch.setenv("WIRESCOPE_BIND_HOST", "127.0.0.1")
    get_settings.cache_clear()
    kwargs = uvicorn_run_kwargs(get_settings())
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["proxy_headers"] is True
    assert kwargs["forwarded_allow_ips"] == "127.0.0.1"
    assert "ssl_certfile" not in kwargs
    get_settings.cache_clear()


def test_uvicorn_kwargs_direct_tls(monkeypatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    monkeypatch.setenv("WIRESCOPE_TLS_CERTFILE", str(cert))
    monkeypatch.setenv("WIRESCOPE_TLS_KEYFILE", str(key))
    monkeypatch.setenv("WIRESCOPE_BIND_PORT", "8443")
    get_settings.cache_clear()
    kwargs = uvicorn_run_kwargs(get_settings())
    assert kwargs["ssl_certfile"] == str(cert)
    assert kwargs["ssl_keyfile"] == str(key)
    assert kwargs["port"] == 8443
    get_settings.cache_clear()


def test_health_reports_transport_flags(api_context):
    app, _service, _evidence, _environment = api_context
    health = http_request(app, "GET", "/api/health", auth=False)
    payload = health.json()
    assert payload["status"] == "ok"
    assert payload["cookie_secure"] is False
    assert payload["trust_proxy"] is False
    assert payload["tls"] is False


def test_self_signed_argv_is_openssl_without_shell():
    argv = self_signed_argv(
        certfile=Path("/etc/wirescope/tls/cert.pem"),
        keyfile=Path("/etc/wirescope/tls/key.pem"),
        common_name="wirescope.example",
    )
    assert argv[0] == "openssl"
    assert "-nodes" in argv
    assert "/CN=wirescope.example" in argv
    assert not any(";" in item or "|" in item for item in argv)


def test_validate_tls_settings_both_or_neither():
    validate_tls_settings("", "")
    try:
        validate_tls_settings("/tmp/cert.pem", "")
    except ValueError as exc:
        assert "together" in str(exc)
    else:
        raise AssertionError("cert without key must fail")


def test_lan_warnings_prefer_proxy_over_public_http():
    public = lan_warnings(
        bind_host="0.0.0.0",
        trust_proxy=False,
        tls_enabled=False,
    )
    assert any("public HTTP" in item for item in public)
    trusted = lan_warnings(
        bind_host="0.0.0.0",
        trust_proxy=True,
        tls_enabled=False,
    )
    assert any("127.0.0.1" in item for item in trusted)


def test_production_env_records_trust_proxy_without_secrets():
    text = production_env_text(
        InstallPaths(),
        bind_host="127.0.0.1",
        bind_port=8000,
        trust_proxy=True,
        tls_certfile="/etc/wirescope/tls/cert.pem",
        tls_keyfile="/etc/wirescope/tls/key.pem",
    )
    assert "WIRESCOPE_TRUST_PROXY=true" in text
    assert "WIRESCOPE_SESSION_COOKIE_SECURE=true" in text
    assert "WIRESCOPE_TLS_CERTFILE=/etc/wirescope/tls/cert.pem" in text
    assert "BEGIN " not in text
    assert "PASSWORD" not in text
