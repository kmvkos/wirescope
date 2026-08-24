"""Validate tcpdump/libpcap capture filters before passing them to dumpcap."""

from __future__ import annotations

import re


BPF_MAX_LENGTH = 512
_ALLOWED = re.compile(r"^[A-Za-z0-9 \t.:/()\[\]!<>=&|^*+,-]+$")


class BpfFilterError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def normalize_bpf_filter(
    value: str | None,
    *,
    max_length: int = BPF_MAX_LENGTH,
) -> str | None:
    """Return a stripped filter, or None for “capture everything the NIC sees”.

    The value is passed as a single dumpcap `-f` argv element. Reject shell
    metacharacters, quotes, and control characters even though there is no
    shell interpolation.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise BpfFilterError("invalid_filter", "Capture filter must be text")
    if "\x00" in value or any(
        ord(character) < 32 and character not in " \t" for character in value
    ):
        raise BpfFilterError(
            "invalid_filter",
            "Capture filter contains control characters",
        )
    stripped = " ".join(value.split())
    if not stripped:
        return None
    if len(stripped) > max_length:
        raise BpfFilterError(
            "invalid_filter",
            f"Capture filter must be at most {max_length} characters",
        )
    if not _ALLOWED.fullmatch(stripped):
        raise BpfFilterError(
            "invalid_filter",
            "Capture filter must be tcpdump syntax without quotes or shell characters",
        )
    if stripped.count("(") != stripped.count(")"):
        raise BpfFilterError(
            "invalid_filter",
            "Capture filter has unmatched parentheses",
        )
    if stripped.count("[") != stripped.count("]"):
        raise BpfFilterError(
            "invalid_filter",
            "Capture filter has unmatched brackets",
        )
    return stripped
