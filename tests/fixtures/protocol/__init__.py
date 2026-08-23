"""Sanitised protocol-audit tool fixtures. Parser tests never touch a network."""

from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent


def fixture_text(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")
