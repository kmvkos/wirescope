"""Wait until the local API answers /api/health."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


def health_url(host: str | None = None, port: int | None = None) -> str:
    bind_host = host or os.getenv("WIRESCOPE_BIND_HOST", "127.0.0.1")
    if bind_host in {"0.0.0.0", "::"}:
        bind_host = "127.0.0.1"
    bind_port = port if port is not None else int(os.getenv("WIRESCOPE_BIND_PORT", "8000"))
    tls = bool(
        os.getenv("WIRESCOPE_TLS_CERTFILE", "").strip()
        and os.getenv("WIRESCOPE_TLS_KEYFILE", "").strip()
    )
    scheme = "https" if tls else "http"
    return f"{scheme}://{bind_host}:{bind_port}/api/health"


def _ssl_context(url: str) -> ssl.SSLContext | None:
    if not url.startswith("https://"):
        return None
    context = ssl.create_default_context()
    hostname = urlparse(url).hostname or ""
    if hostname in {"127.0.0.1", "localhost", "::1"}:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def wait_ready(*, url: str, timeout_seconds: float = 60.0, interval: float = 0.25) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not contacted"
    context = _ssl_context(url)
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2, context=context) as response:
                if 200 <= response.status < 300:
                    return
                last_error = f"HTTP {response.status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(interval)
    raise SystemExit(f"WireScope API was not ready at {url}: {last_error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wait for WireScope /api/health")
    parser.add_argument("--url", default="")
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    wait_ready(url=args.url or health_url(), timeout_seconds=args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
