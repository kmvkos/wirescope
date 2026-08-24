"""Production API process entry: bind from settings, never as root."""

import os

import uvicorn

from config.settings import get_settings


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("WireScope API must not run as root")
    settings = get_settings()
    uvicorn.run(
        "backend.app:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
        proxy_headers=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
