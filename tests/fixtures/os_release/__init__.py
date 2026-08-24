"""os-release fixtures for generic Linux installer detection."""

from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent


def os_release(name: str) -> str:
    return (FIXTURE_DIR / f"{name}.txt").read_text(encoding="utf-8")
