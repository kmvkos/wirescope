"""Canonical identity helpers for inventory correlation."""

import ipaddress
import re


MAC_RE = re.compile(r"[^0-9A-Fa-f]")


def canonical_mac(value: str | None) -> str | None:
    if not value:
        return None
    hex_chars = MAC_RE.sub("", value)
    if len(hex_chars) != 12:
        return None
    return ":".join(
        hex_chars[index:index + 2].upper()
        for index in range(0, 12, 2)
    )


def canonical_ip(value: str) -> tuple[str, int]:
    address = ipaddress.ip_address(value.strip())
    return str(address), address.version


def escape_like(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
