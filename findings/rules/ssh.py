"""SSH algorithm findings from normalized ssh_algorithms observations."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import WEAK_SSH_BY_FAMILY
from findings.copy import SSH_WEAK, ssh_rationale
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    as_string_list,
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)


RULE_ID = "WS-SSH-WEAK-ALGORITHMS"
RULE_VERSION = "1"
FAMILY = "ssh"


class WeakSshAlgorithmsRule:
    id = RULE_ID
    version = RULE_VERSION
    family = FAMILY

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        observations = usable_observations(context, {"ssh_algorithms"})
        for group in grouped_by_service(observations).values():
            weak: dict[str, list[str]] = {}
            for item in group:
                for family, catalog in WEAK_SSH_BY_FAMILY.items():
                    names = as_string_list(item.data.get(family))
                    matched = [name for name in names if name.lower() in catalog]
                    if matched:
                        weak.setdefault(family, [])
                        for name in matched:
                            if name not in weak[family]:
                                weak[family].append(name)
            if not weak:
                continue
            families = ", ".join(sorted(weak))
            sample = group[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=SSH_WEAK["title"],
                    severity=_ssh_severity(weak),
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=SSH_WEAK["description"],
                    rationale=ssh_rationale(families),
                    recommendation=SSH_WEAK["recommendation"],
                    data={"weak_algorithms": weak, "families": sorted(weak)},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


def _ssh_severity(weak: dict[str, list[str]]) -> Severity:
    names = {name.lower() for values in weak.values() for name in values}
    high_tokens = {
        "diffie-hellman-group1-sha1",
        "ssh-dss",
        "ssh-dsa",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "3des-cbc",
        "des-cbc",
        "hmac-md5",
        "hmac-md5-96",
    }
    if names & high_tokens:
        return Severity.HIGH
    if weak.get("encryption") or weak.get("kex"):
        return Severity.MEDIUM
    return Severity.LOW
