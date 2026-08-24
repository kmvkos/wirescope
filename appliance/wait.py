"""Wait until the local API answers /api/health."""

from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.error
import urllib.request


def health_url(host: str | None = None, port: int | None = None) -> str:
    bind_host = host or os.getenv("WIRESCOPE_BIND_HOST", "127.0.0.1")
    if bind_host in {"0.0.0.0", "::"}:
        bind_host = "127.0.0.1"
    bind_port = port if port is not None else int(os.getenv("WIRESCOPE_BIND_PORT", "8000"))
    return f"http://{bind_host}:{bind_port}/api/health"


def wait_ready(*, url: str, timeout_seconds: float = 60.0, interval: float = 0.25) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not contacted"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
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
