"""DNS recursion and identity-disclosure findings."""

from engine.passive_models import ConfidenceLevel
from findings.copy import (
    DNS_RECURSION,
    DNS_VERSION,
    dns_identity_rationale,
    dns_recursion_rationale,
)
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)


class DnsRecursionRule:
    id = "WS-DNS-RECURSION"
    version = "1"
    family = "dns"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"dns_flags"})
        ).values():
            recursive = [
                item
                for item in group
                if item.data.get("recursion_available") is True
            ]
            if not recursive:
                continue
            sample = recursive[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=DNS_RECURSION["title"],
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=DNS_RECURSION["description"],
                    rationale=dns_recursion_rationale(sample.data.get("flags")),
                    recommendation=DNS_RECURSION["recommendation"],
                    data={
                        "flags": sample.data.get("flags") or [],
                        "recursion_available": True,
                        "rcode": sample.data.get("rcode"),
                    },
                    observations=recursive,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class DnsVersionDisclosedRule:
    id = "WS-DNS-VERSION-DISCLOSED"
    version = "1"
    family = "dns"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"dns_identity"})
        ).values():
            disclosed = [
                item
                for item in group
                if item.data.get("version") or item.data.get("hostname")
            ]
            if not disclosed:
                continue
            sample = disclosed[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=DNS_VERSION["title"],
                    severity=Severity.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=DNS_VERSION["description"],
                    rationale=dns_identity_rationale(
                        sample.data.get("version"),
                        sample.data.get("hostname"),
                    ),
                    recommendation=DNS_VERSION["recommendation"],
                    data={
                        "version": sample.data.get("version"),
                        "hostname": sample.data.get("hostname"),
                    },
                    observations=disclosed,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings
