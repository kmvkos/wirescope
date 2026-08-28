"""Safety helpers for operator-supplied PCAP/PCAPNG files."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import uuid
from urllib.parse import unquote


# Libpcap variants understood by Wireshark/tshark:
# - standard microsecond timestamps (both endian orders)
# - nanosecond timestamps (both endian orders)
# - Alexey Kuznetsov / ss991029 "modified pcap" (both endian orders)
#
# WireScope does not parse packet records at import time; downstream tshark is
# the canonical decoder. The import boundary only needs to distinguish a known
# capture container from arbitrary uploaded bytes.
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # standard, little-endian
    b"\xa1\xb2\xc3\xd4",  # standard, big-endian
    b"\x4d\x3c\xb2\xa1",  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond, big-endian
    b"\x34\xcd\xb2\xa1",  # modified pcap, little-endian
    b"\xa1\xb2\xcd\x34",  # modified pcap, big-endian
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
_PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"
_SAFE_NAME = re.compile(r"[^A-Za-zА-Яа-яЁё0-9._ ()+\-]+")


class PcapImportValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class PcapFileInfo:
    format: str
    extension: str
    content_type: str
    size: int
    sha256: str


def sanitize_original_filename(raw: str | None) -> str:
    text = unquote(str(raw or "")).replace("\\", "/")
    text = text.rsplit("/", 1)[-1].strip().strip(".")
    text = _SAFE_NAME.sub("_", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "imported-capture"
    return text[:128]


def import_staging_path(evidence_root: Path, token: str) -> Path:
    try:
        parsed = uuid.UUID(str(token))
    except ValueError as exc:
        raise PcapImportValidationError(
            "invalid_import_token",
            "Import staging token is invalid",
        ) from exc
    canonical = str(parsed)
    if canonical != str(token):
        raise PcapImportValidationError(
            "invalid_import_token",
            "Import staging token is invalid",
        )
    directory = (evidence_root / "_imports").resolve()
    root = evidence_root.resolve()
    if not directory.is_relative_to(root):
        raise PcapImportValidationError(
            "unsafe_import_path",
            "Import staging directory escaped evidence storage",
        )
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory / f"pcap.tmp-{canonical}"


def inspect_pcap_file(path: Path, *, max_bytes: int) -> PcapFileInfo:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PcapImportValidationError(
            "pcap_import_unavailable",
            "Uploaded PCAP staging file is unavailable",
        ) from exc
    if size <= 0:
        raise PcapImportValidationError(
            "pcap_import_empty",
            "Uploaded file is empty",
        )
    if size > max_bytes:
        raise PcapImportValidationError(
            "pcap_import_too_large",
            "Uploaded PCAP exceeds the configured size limit",
        )

    with path.open("rb") as handle:
        header = handle.read(32)
        digest = hashlib.sha256()
        handle.seek(0)
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)

    format_name, extension, content_type = _detect_format(header, size)
    return PcapFileInfo(
        format=format_name,
        extension=extension,
        content_type=content_type,
        size=size,
        sha256=digest.hexdigest(),
    )


def _detect_format(header: bytes, size: int) -> tuple[str, str, str]:
    if header[:4] in _PCAP_MAGIC:
        if size < 24 or len(header) < 24:
            raise PcapImportValidationError(
                "pcap_import_truncated",
                "Classic PCAP header is truncated",
            )
        return "pcap", ".pcap", "application/vnd.tcpdump.pcap"

    if header[:4] == _PCAPNG_MAGIC:
        if size < 28 or len(header) < 28:
            raise PcapImportValidationError(
                "pcap_import_truncated",
                "PCAPNG section header is truncated",
            )
        bom = header[8:12]
        if bom == _PCAPNG_BOM_LE:
            byte_order = "little"
        elif bom == _PCAPNG_BOM_BE:
            byte_order = "big"
        else:
            raise PcapImportValidationError(
                "pcap_import_invalid",
                "PCAPNG byte-order magic is invalid",
            )
        block_length = int.from_bytes(header[4:8], byte_order)
        if block_length < 28 or block_length > size:
            raise PcapImportValidationError(
                "pcap_import_invalid",
                "PCAPNG section header length is invalid",
            )
        trailing = int.from_bytes(header[block_length - 4 : block_length], byte_order) if block_length <= len(header) else None
        if trailing is not None and trailing != block_length:
            raise PcapImportValidationError(
                "pcap_import_invalid",
                "PCAPNG section header length markers disagree",
            )
        return "pcapng", ".pcapng", "application/x-pcapng"

    magic = " ".join(f"{byte:02x}" for byte in header[:4]) or "<empty>"
    raise PcapImportValidationError(
        "pcap_import_unsupported",
        f"File is not a supported PCAP or PCAPNG capture (magic: {magic})",
    )


def durable_write_stream(path: Path, chunks, *, max_bytes: int) -> int:
    """Write an iterable of byte chunks atomically enough for staging use.

    The caller owns cleanup on validation or database failure. The filename is
    already random and confined to the evidence staging directory.
    """

    total = 0
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        for chunk in chunks:
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise PcapImportValidationError(
                    "pcap_import_too_large",
                    "Uploaded PCAP exceeds the configured size limit",
                )
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    return total
