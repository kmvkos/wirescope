"""SNMP unauthenticated-exposure findings."""

from engine.passive_models import ConfidenceLevel
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)


class SnmpUnauthenticatedRule:
    id = "WS-SNMP-UNAUTHENTICATED"
    version = "1"
    family = "snmp"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"snmp_unauthenticated"})
        ).values():
            responded = [
                item for item in group if item.data.get("responded") is True
            ]
            if not responded:
                continue
            sample = responded[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title="SNMP responded without authentication",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "An SNMPv3 noAuthNoPriv probe received a response."
                    ),
                    rationale=(
                        "snmp_unauthenticated.responded is true"
                        + (
                            f" (usm_indicator={sample.data.get('usm_indicator')})"
                            if sample.data.get("usm_indicator")
                            else ""
                        )
                        + "."
                    ),
                    recommendation=(
                        "Require SNMPv3 authentication and privacy, and "
                        "restrict SNMP to management networks. Community "
                        "guessing is outside the default profile."
                    ),
                    data={
                        "responded": True,
                        "auth": sample.data.get("auth"),
                        "version": sample.data.get("version"),
                        "usm_indicator": sample.data.get("usm_indicator"),
                        "sys_descr": sample.data.get("sys_descr"),
                    },
                    observations=responded,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings
