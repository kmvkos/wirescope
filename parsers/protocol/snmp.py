"""Parse unauthenticated SNMPv3 probe output.

Community-string guessing is out of scope. A missing response is not
interpreted as SNMP being absent.
"""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_TIMEOUT = re.compile(r"Timeout: No Response|No Response from", re.I)
_ENGINE = re.compile(r"(engineBoots|engineID|usmStatsUnknownEngineIDs|Unknown user name|authorizationError)", re.I)
_SYS_DESCR = re.compile(r"sysDescr(?:\.0)?\s*=\s*(?:STRING:\s*)?(.+)$", re.I | re.M)


def parse_snmpget(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="snmpget",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    sys_descr = None
    match = _SYS_DESCR.search(text)
    if match:
        sys_descr = match.group(1).strip()
        return [
            ObservationDraft(
                kind="snmp_unauthenticated",
                data={
                    "responded": True,
                    "sys_descr": sys_descr,
                    "auth": "none",
                    "version": "3",
                },
                confidence=ConfidenceLevel.HIGH,
                source="snmpget",
            )
        ]
    if _TIMEOUT.search(text) or not text.strip():
        return [
            ObservationDraft(
                kind="snmp_unauthenticated",
                data={
                    "responded": False,
                    "auth": "none",
                    "version": "3",
                    "note": (
                        "No SNMPv3 unauthenticated response. Community "
                        "guessing and SNMP walks are outside the default profile."
                    ),
                },
                confidence=ConfidenceLevel.MEDIUM,
                source="snmpget",
            )
        ]
    engine = _ENGINE.search(text)
    if engine:
        return [
            ObservationDraft(
                kind="snmp_unauthenticated",
                data={
                    "responded": True,
                    "auth": "none",
                    "version": "3",
                    "usm_indicator": engine.group(1),
                },
                confidence=ConfidenceLevel.HIGH,
                source="snmpget",
            )
        ]
    return [malformed_observation("snmpget", "snmpget output was not recognised")]
