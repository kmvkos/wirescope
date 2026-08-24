"""Build uvicorn kwargs for the unprivileged API process."""

from __future__ import annotations

from config.settings import Settings


def uvicorn_run_kwargs(settings: Settings) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "app": "backend.app:app",
        "host": settings.bind_host,
        "port": settings.bind_port,
        "reload": False,
        "proxy_headers": settings.trust_proxy,
        "access_log": False,
    }
    if settings.trust_proxy:
        kwargs["forwarded_allow_ips"] = "127.0.0.1"
    if settings.tls_enabled:
        kwargs["ssl_certfile"] = settings.tls_certfile
        kwargs["ssl_keyfile"] = settings.tls_keyfile
    return kwargs
