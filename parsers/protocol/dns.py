"""Parse dig output into DNS protocol observations."""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_FLAGS = re.compile(r";; flags:\s*([^;]+);", re.I)
_TXT = re.compile(r'version\.bind\.\s+\d+\s+CH\s+TXT\s+"([^"]*)"', re.I)
_HOSTNAME = re.compile(r'hostname\.bind\.\s+\d+\s+CH\s+TXT\s+"([^"]*)"', re.I)
_ID_SERVER = re.compile(r'id\.server\.\s+\d+\s+CH\s+TXT\s+"([^"]*)"', re.I)
_STATUS = re.compile(r"status:\s*([A-Z]+)", re.I)
_HEADER = re.compile(r"^; <<>> DiG ", re.M)


def parse_dig(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="dig",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if not text.strip() or (
        _HEADER.search(text) is None and "flags:" not in text.lower()
    ):
        if "connection timed out" in text.lower() or "no servers could be reached" in text.lower():
            return [
                ObservationDraft(
                    kind="dns_unreachable",
                    data={"message": "dig received no response from the in-scope resolver"},
                    confidence=ConfidenceLevel.MEDIUM,
                    source="dig",
                )
            ]
        return [malformed_observation("dig", "dig output was not a recognisable DNS message")]

    flags_match = _FLAGS.search(text)
    flags = []
    if flags_match:
        flags = [item.strip() for item in flags_match.group(1).split() if item.strip()]
    rcode = None
    status_match = _STATUS.search(text)
    if status_match:
        rcode = status_match.group(1).upper()

    drafts: list[ObservationDraft] = []
    version = _search(_TXT, text)
    hostname = _search(_HOSTNAME, text) or _search(_ID_SERVER, text)
    if version or hostname:
        drafts.append(
            ObservationDraft(
                kind="dns_identity",
                data={"version": version, "hostname": hostname},
                confidence=ConfidenceLevel.HIGH,
                source="dig",
            )
        )
    drafts.append(
        ObservationDraft(
            kind="dns_flags",
            data={
                "flags": flags,
                "recursion_available": "ra" in flags,
                "recursion_desired": "rd" in flags,
                "authoritative": "aa" in flags,
                "rcode": rcode,
            },
            confidence=ConfidenceLevel.HIGH,
            source="dig",
        )
    )
    return drafts


def _search(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if match is None:
        return None
    return match.group(1).strip()
