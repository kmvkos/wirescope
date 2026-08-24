"""LDAP anonymous-bind findings."""

from engine.passive_models import ConfidenceLevel
from findings.copy import LDAP_ANON, ldap_rationale
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)


class LdapAnonymousBindRule:
    id = "WS-LDAP-ANONYMOUS-BIND"
    version = "1"
    family = "ldap"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        kinds = {"ldap_rootdse", "ldap_anonymous_bind"}
        for group in grouped_by_service(usable_observations(context, kinds)).values():
            accepted = [
                item for item in group if item.data.get("anonymous_bind") is True
            ]
            if not accepted:
                continue
            sample = accepted[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=LDAP_ANON["title"],
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=LDAP_ANON["description"],
                    rationale=ldap_rationale(),
                    recommendation=LDAP_ANON["recommendation"],
                    data={
                        "anonymous_bind": True,
                        "attributes": sample.data.get("attributes") or {},
                    },
                    observations=accepted,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings
