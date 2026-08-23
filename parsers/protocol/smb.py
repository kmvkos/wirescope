"""Parse unauthenticated smbclient listing output."""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_SHARE = re.compile(
    r"^\s*(\S+)\s+(Disk|IPC|Printer|Device)\s*(.*)$",
    re.I,
)
_DENIED = re.compile(
    r"NT_STATUS_(ACCESS_DENIED|LOGON_FAILURE|ACCOUNT_DISABLED|INVALID_PARAMETER)",
    re.I,
)
_SUCCESS = re.compile(r"(Anonymous login successful|Sharename)", re.I)


def parse_smbclient(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="smbclient",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    denied = _DENIED.search(text)
    if denied:
        return [
            ObservationDraft(
                kind="smb_null_session",
                data={
                    "accepted": False,
                    "status": denied.group(0).upper(),
                },
                confidence=ConfidenceLevel.HIGH,
                source="smbclient",
            )
        ]
    shares: list[dict[str, str]] = []
    for line in text.splitlines():
        match = _SHARE.match(line)
        if match:
            shares.append(
                {
                    "name": match.group(1),
                    "type": match.group(2).lower(),
                    "comment": match.group(3).strip(),
                }
            )
    if shares or _SUCCESS.search(text):
        return [
            ObservationDraft(
                kind="smb_null_session",
                data={
                    "accepted": True,
                    "share_count": len(shares),
                    "shares": shares,
                },
                confidence=ConfidenceLevel.HIGH,
                source="smbclient",
            )
        ]
    if not text.strip():
        return [malformed_observation("smbclient", "smbclient produced no output")]
    return [
        ObservationDraft(
            kind="smb_probe_result",
            data={"message": text.splitlines()[0][:256]},
            confidence=ConfidenceLevel.MEDIUM,
            source="smbclient",
        )
    ]
