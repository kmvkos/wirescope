"""Exposed insecure management protocols from inventory services."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import (
    INSECURE_MANAGEMENT_NAMES,
    INSECURE_MANAGEMENT_PORTS,
    NAME_SEVERITY,
)
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import draft, inventory_dedupe_key
from inventory.models import ServiceRecord


class InsecureManagementRule:
    id = "WS-MGMT-INSECURE-PROTOCOL"
    version = "1"
    family = "management"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for service in context.services:
            match = _match(service)
            if match is None:
                continue
            name, severity = match
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=f"Insecure {name} management service is exposed",
                    severity=severity,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=service.asset_id,
                    service_id=service.id,
                    description=(
                        f"Inventory records an open {name} service on "
                        f"{service.protocol}/{service.port}."
                    ),
                    rationale=(
                        "Normalized inventory service "
                        f"{service.service_name or name} is open on "
                        f"{service.protocol}/{service.port}. This is not a "
                        "protocol-audit finding; the service was not brute "
                        "forced."
                    ),
                    recommendation=(
                        f"Disable {name} on production networks, or confine "
                        "it to a dedicated management plane with "
                        "authentication."
                    ),
                    data={
                        "protocol": service.protocol,
                        "port": service.port,
                        "service_name": service.service_name,
                        "product": service.product,
                        "matched_as": name,
                        "source": "inventory_service",
                    },
                    evidence_artifact_ids=[],
                    dedupe_key=inventory_dedupe_key(service),
                )
            )
        return findings


def _match(service: ServiceRecord) -> tuple[str, Severity] | None:
    if service.state != "open":
        return None
    name = (service.service_name or "").lower().strip()
    if name in INSECURE_MANAGEMENT_NAMES:
        rank = NAME_SEVERITY.get(name, "medium")
        return name, Severity(rank)
    port_match = INSECURE_MANAGEMENT_PORTS.get(
        (service.port, service.protocol.lower())
    )
    if port_match is None:
        return None
    if name and name not in INSECURE_MANAGEMENT_NAMES and name not in {
        port_match[0],
        "unknown",
        "",
    }:
        # Do not treat a well-known port as telnet/ftp when Nmap named a
        # different modern service.
        return None
    return port_match[0], Severity(port_match[1])
