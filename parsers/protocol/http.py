"""Parse curl header/body output into HTTP protocol observations."""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_STATUS = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$", re.I)
_HEADER = re.compile(r"^([A-Za-z0-9!#$%&'*+\-.^_`|~]+):\s*(.*)$")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
INTERESTING_HEADERS = {
    "server",
    "content-type",
    "content-length",
    "location",
    "www-authenticate",
    "strict-transport-security",
    "x-powered-by",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "cache-control",
}


def parse_curl_http(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="curl",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = result.stdout
    if not text.strip():
        return [malformed_observation("curl", "curl produced no HTTP output")]

    header_block, body = _split_headers(text)
    status_code = None
    reason = None
    headers: dict[str, str] = {}
    for line in header_block.splitlines():
        stripped = line.strip("\r")
        status_match = _STATUS.match(stripped)
        if status_match:
            status_code = int(status_match.group(1))
            reason = (status_match.group(2) or "").strip() or None
            headers = {}
            continue
        header_match = _HEADER.match(stripped)
        if header_match:
            name = header_match.group(1).lower()
            if name in INTERESTING_HEADERS and name not in headers:
                headers[name] = header_match.group(2).strip()

    if status_code is None:
        return [malformed_observation("curl", "curl output had no HTTP status line")]

    title = None
    title_match = _TITLE.search(body)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:256] or None

    return [
        ObservationDraft(
            kind="http_response",
            data={
                "status_code": status_code,
                "reason": reason,
                "title": title,
                "headers": headers,
            },
            confidence=ConfidenceLevel.HIGH,
            source="curl",
        )
    ]


def _split_headers(text: str) -> tuple[str, str]:
    chunks = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    if len(chunks) == 1:
        return chunks[0], ""
    return chunks[0], chunks[1]
