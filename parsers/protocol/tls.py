"""Parse OpenSSL s_client output into TLS protocol observations."""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_PROTOCOL = re.compile(
    r"(?:Protocol(?: version)?|New,)\s*:?\s*(TLS[\w.]+|SSLv[\w.]+|TLSv1(?:\.\d)?)",
    re.I,
)
_PROTOCOL_NEW = re.compile(r"New,\s*(TLS[\w.]+|SSLv[\w.]+)", re.I)
_CIPHER = re.compile(
    r"(?:Ciphersuite:\s*|Cipher is\s+|Cipher\s*:\s*)([A-Z0-9_\-]+)",
    re.I,
)
_SUBJECT = re.compile(r"^subject\s*=\s*(.+)$", re.I | re.M)
_ISSUER = re.compile(r"^issuer\s*=\s*(.+)$", re.I | re.M)
_NOT_BEFORE = re.compile(r"notBefore\s*=\s*(.+)$", re.I | re.M)
_NOT_AFTER = re.compile(r"notAfter\s*=\s*(.+)$", re.I | re.M)
_VERIFY = re.compile(r"Verify return code:\s*(\d+)\s*(?:\((.+)\))?", re.I)
_CONNECTED = re.compile(r"^CONNECTED\(", re.M)
_BRIEF_PROTOCOL = re.compile(r"Protocol version:\s*(.+)$", re.I | re.M)
_BRIEF_CIPHER = re.compile(r"Ciphersuite:\s*(.+)$", re.I | re.M)
_PEER_CERT = re.compile(r"Peer certificate:\s*(.+)$", re.I | re.M)


def parse_openssl_sclient(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="openssl",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = "\n".join(
        part for part in (result.stdout, result.stderr) if part
    )
    if not text.strip():
        return [malformed_observation("openssl", "openssl produced no output")]

    protocol = _first(_BRIEF_PROTOCOL, text) or _first(_PROTOCOL_NEW, text)
    if protocol is None:
        match = _PROTOCOL.search(text)
        protocol = match.group(1) if match else None
    cipher = _first(_BRIEF_CIPHER, text)
    if cipher is None:
        match = _CIPHER.search(text)
        cipher = match.group(1) if match else None
    subject = _first(_SUBJECT, text) or _first(_PEER_CERT, text)
    issuer = _first(_ISSUER, text)
    not_before = _first(_NOT_BEFORE, text)
    not_after = _first(_NOT_AFTER, text)
    verify_code = None
    verify_text = None
    verify = _VERIFY.search(text)
    if verify:
        verify_code = int(verify.group(1))
        verify_text = (verify.group(2) or "").strip() or None

    connected = bool(_CONNECTED.search(text) or protocol or cipher)
    if not connected:
        return [malformed_observation("openssl", "openssl output had no handshake fields")]

    drafts: list[ObservationDraft] = []
    if protocol or cipher:
        drafts.append(
            ObservationDraft(
                kind="tls_session",
                data={
                    "protocol": protocol,
                    "cipher": cipher,
                },
                confidence=ConfidenceLevel.HIGH,
                source="openssl",
            )
        )
    if subject or issuer or not_before or not_after or verify_code is not None:
        drafts.append(
            ObservationDraft(
                kind="tls_certificate",
                data={
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "verify_code": verify_code,
                    "verify_message": verify_text,
                },
                confidence=ConfidenceLevel.HIGH,
                source="openssl",
            )
        )
    if not drafts:
        return [malformed_observation("openssl", "openssl handshake fields were empty")]
    return drafts


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if match is None:
        return None
    return match.group(1).strip()
