"""Parse anonymous ldapsearch base DSE output."""

import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_ATTR = re.compile(r"^([A-Za-z][\w-]*)\s*:\s*(.+)$")
_BIND_FAIL = re.compile(
    r"(Confidentiality required|Invalid credentials|inappropriateAuthentication|operationsError)",
    re.I,
)
INTERESTING = {
    "namingcontexts",
    "defaultnamingcontext",
    "dnshostname",
    "ldapservicename",
    "rootdomainnamingcontext",
    "supportedldapversion",
    "supportedsaslmechanisms",
}


def parse_ldapsearch(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="ldapsearch",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    attributes: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = _ATTR.match(line.strip())
        if not match:
            continue
        name = match.group(1).lower()
        if name not in INTERESTING:
            continue
        attributes.setdefault(name, []).append(match.group(2).strip())
    if attributes:
        return [
            ObservationDraft(
                kind="ldap_rootdse",
                data={
                    "anonymous_bind": True,
                    "attributes": attributes,
                },
                confidence=ConfidenceLevel.HIGH,
                source="ldapsearch",
            )
        ]
    denied = _BIND_FAIL.search(text)
    if denied:
        return [
            ObservationDraft(
                kind="ldap_anonymous_bind",
                data={
                    "anonymous_bind": False,
                    "status": denied.group(1),
                },
                confidence=ConfidenceLevel.HIGH,
                source="ldapsearch",
            )
        ]
    if not text.strip():
        return [malformed_observation("ldapsearch", "ldapsearch produced no output")]
    return [
        ObservationDraft(
            kind="ldap_anonymous_bind",
            data={
                "anonymous_bind": False,
                "message": text.splitlines()[0][:256],
            },
            confidence=ConfidenceLevel.MEDIUM,
            source="ldapsearch",
        )
    ]
