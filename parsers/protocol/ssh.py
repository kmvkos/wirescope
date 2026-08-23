"""Parse ssh-audit JSON or text output into protocol observations.

Parser is independent of persistence. Weak algorithms are recorded as
observed algorithm lists, not findings.
"""

import json
import re

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from protocol_audits.status import malformed_observation, tool_status_observation
from providers.tools import ToolResult


_TEXT_BANNER = re.compile(r"(?:banner|remote software version)\s*[:=]\s*(.+)$", re.I)
_TEXT_ALGO = re.compile(
    r"^\s*\((kex|key|enc|mac|host.?key|cipher)\)\s+"
    r"(?:algorithm\s*)?[:=]\s*(.+)$",
    re.I,
)


def parse_ssh_audit(result: ToolResult) -> list[ObservationDraft]:
    status = tool_status_observation(
        result,
        source="ssh-audit",
        parse_on_nonzero_exit=True,
    )
    if status is not None:
        return [status]
    text = result.stdout.strip() or result.stderr.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [malformed_observation("ssh-audit", "ssh-audit JSON is invalid")]
        return _from_json(payload)
    return _from_text(text)


def _from_json(payload: object) -> list[ObservationDraft]:
    if isinstance(payload, list) and payload:
        payload = payload[0]
    if not isinstance(payload, dict):
        return [malformed_observation("ssh-audit", "ssh-audit JSON root is not an object")]
    drafts: list[ObservationDraft] = []
    banner = payload.get("banner")
    software = None
    protocol = None
    raw = None
    if isinstance(banner, dict):
        software = banner.get("software") or banner.get("raw")
        raw = banner.get("raw")
        protocol = banner.get("protocol")
    elif isinstance(banner, str):
        software = banner
        raw = banner
    if software or raw:
        drafts.append(
            ObservationDraft(
                kind="ssh_banner",
                data={
                    "software": software,
                    "raw": raw,
                    "protocol": protocol,
                },
                confidence=ConfidenceLevel.HIGH,
                source="ssh-audit",
            )
        )
    algorithms = {
        "kex": _algorithm_names(payload.get("kex") or payload.get("kexalgos")),
        "host_key": _algorithm_names(
            payload.get("key") or payload.get("keyalgos") or payload.get("hostkey")
        ),
        "encryption": _algorithm_names(
            payload.get("enc") or payload.get("ciphers") or payload.get("encalgos")
        ),
        "mac": _algorithm_names(payload.get("mac") or payload.get("macalgos")),
    }
    if any(algorithms.values()):
        drafts.append(
            ObservationDraft(
                kind="ssh_algorithms",
                data=algorithms,
                confidence=ConfidenceLevel.HIGH,
                source="ssh-audit",
            )
        )
    if not drafts:
        return [malformed_observation("ssh-audit", "ssh-audit JSON had no banner or algorithms")]
    return drafts


def _from_text(text: str) -> list[ObservationDraft]:
    algorithms: dict[str, list[str]] = {
        "kex": [],
        "host_key": [],
        "encryption": [],
        "mac": [],
    }
    banner = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        banner_match = _TEXT_BANNER.search(stripped)
        if banner_match and banner is None:
            banner = banner_match.group(1).strip()
            continue
        algo_match = _TEXT_ALGO.match(stripped)
        if algo_match:
            family = _family(algo_match.group(1))
            names = [
                item.strip()
                for item in algo_match.group(2).replace(",", " ").split()
                if item.strip() and not item.startswith("(")
            ]
            algorithms[family].extend(names)
    drafts: list[ObservationDraft] = []
    if banner:
        drafts.append(
            ObservationDraft(
                kind="ssh_banner",
                data={"software": banner, "raw": banner},
                confidence=ConfidenceLevel.HIGH,
                source="ssh-audit",
            )
        )
    if any(algorithms.values()):
        drafts.append(
            ObservationDraft(
                kind="ssh_algorithms",
                data={key: _dedupe(value) for key, value in algorithms.items()},
                confidence=ConfidenceLevel.HIGH,
                source="ssh-audit",
            )
        )
    if not drafts:
        return [malformed_observation("ssh-audit", "ssh-audit text had no banner or algorithms")]
    return drafts


def _algorithm_names(value: object) -> list[str]:
    if value is None:
        return []
    names: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = item.get("algorithm") or item.get("name")
                if isinstance(name, str):
                    names.append(name)
    elif isinstance(value, dict):
        names.extend(_algorithm_names(list(value.values())))
    return _dedupe(names)


def _family(label: str) -> str:
    lowered = label.lower()
    if lowered.startswith("kex"):
        return "kex"
    if "key" in lowered:
        return "host_key"
    if lowered.startswith("mac"):
        return "mac"
    return "encryption"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in values:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
