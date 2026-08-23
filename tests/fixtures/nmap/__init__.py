"""Sanitised Nmap XML fixtures. Parser tests never invoke Nmap."""

from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent


def fixture_path(name: str) -> Path:
    return FIXTURE_DIR / name


def fixture_text(name: str) -> str:
    return fixture_path(name).read_text(encoding="utf-8")


def nmaprun(
    hosts: str,
    *,
    args: str = "nmap -sV",
    up: int = 1,
    down: int = 0,
    finished: bool = True,
) -> str:
    stats = ""
    if finished:
        total = up + down
        stats = (
            "<runstats>"
            '<finished time="1700000001" elapsed="1.00" '
            'summary="Nmap done"/>'
            f'<hosts up="{up}" down="{down}" total="{total}"/>'
            "</runstats>"
        )
    return (
        '<?xml version="1.0"?>'
        f'<nmaprun scanner="nmap" args="{args}" start="1700000000" '
        'version="7.95" xmloutputversion="1.05">'
        f"{hosts}"
        f"{stats}"
        "</nmaprun>"
    )
