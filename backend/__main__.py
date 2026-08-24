"""Production API process entry: bind from settings, never as root."""

import os
from pathlib import Path

import uvicorn

from backend.serve import uvicorn_run_kwargs
from config.settings import get_settings


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("WireScope API must not run as root")
    settings = get_settings()
    if settings.tls_enabled:
        if not Path(settings.tls_certfile).is_file():
            raise SystemExit(f"TLS certificate is missing: {settings.tls_certfile}")
        if not Path(settings.tls_keyfile).is_file():
            raise SystemExit(f"TLS private key is missing: {settings.tls_keyfile}")
    uvicorn.run(**uvicorn_run_kwargs(settings))


if __name__ == "__main__":
    main()
