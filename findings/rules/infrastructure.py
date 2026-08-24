"""Infrastructure findings from stored passive assessment artifacts."""

from typing import Any

from engine.passive_models import ConfidenceLevel
from findings.copy import (
    LLMNR,
    MULTIPLE_DHCP,
    NBNS,
    dhcp_rationale,
    infra_rationale,
)
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import draft


class LlmnrPresentRule:
    id = "WS-INFRA-LLMNR"
    version = "1"
    family = "infrastructure"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        return _sensor_presence(
            context,
            rule_id=self.id,
            sensor="llmnr",
            title=LLMNR["title"],
            description=LLMNR["description"],
            recommendation=LLMNR["recommendation"],
            severity=Severity.MEDIUM,
        )


class NbnsPresentRule:
    id = "WS-INFRA-NBNS"
    version = "1"
    family = "infrastructure"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        return _sensor_presence(
            context,
            rule_id=self.id,
            sensor="nbns",
            title=NBNS["title"],
            description=NBNS["description"],
            recommendation=NBNS["recommendation"],
            severity=Severity.MEDIUM,
        )


class MultipleDhcpServersRule:
    id = "WS-INFRA-MULTIPLE-DHCP"
    version = "1"
    family = "infrastructure"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        if context.passive_result is None:
            return []
        servers = _dhcp_servers(context.passive_result)
        if len(servers) < 2:
            return []
        evidence = (
            [context.passive_artifact_id] if context.passive_artifact_id else []
        )
        return [
            draft(
                rule_id=self.id,
                rule_version="1",
                family="infrastructure",
                title=MULTIPLE_DHCP["title"],
                severity=Severity.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                asset_id=None,
                service_id=None,
                description=MULTIPLE_DHCP["description"],
                rationale=dhcp_rationale(len(servers)),
                recommendation=MULTIPLE_DHCP["recommendation"],
                data={"servers": servers, "source": "passive_assessment"},
                evidence_artifact_ids=evidence,
                dedupe_key="audit",
            )
        ]


def _sensor_presence(
    context: EvaluationContext,
    *,
    rule_id: str,
    sensor: str,
    title: str,
    description: str,
    recommendation: str,
    severity: Severity,
) -> list[FindingDraft]:
    if context.passive_result is None:
        return []
    result = _sensor(context.passive_result, sensor)
    if result is None:
        return []
    status = str(result.get("status") or "")
    hits = int(result.get("hits") or 0)
    if status not in {"detected", "partial"} or hits < 1:
        return []
    evidence = (
        [context.passive_artifact_id] if context.passive_artifact_id else []
    )
    return [
        draft(
            rule_id=rule_id,
            rule_version="1",
            family="infrastructure",
            title=title,
            severity=severity,
            confidence=(
                ConfidenceLevel.HIGH
                if status == "detected"
                else ConfidenceLevel.MEDIUM
            ),
            asset_id=None,
            service_id=None,
            description=description,
            rationale=infra_rationale(sensor, status, hits),
            recommendation=recommendation,
            data={
                "sensor": sensor,
                "status": status,
                "hits": hits,
                "source": "passive_assessment",
            },
            evidence_artifact_ids=evidence,
            dedupe_key="audit",
        )
    ]


def _sensor(document: dict[str, Any], name: str) -> dict[str, Any] | None:
    sensors = document.get("result", {}).get("sensors") or document.get("sensors")
    if not isinstance(sensors, dict):
        return None
    item = sensors.get(name)
    return item if isinstance(item, dict) else None


def _dhcp_servers(document: dict[str, Any]) -> list[str]:
    dhcp = _sensor(document, "dhcpv4") or {}
    summary = dhcp.get("summary") if isinstance(dhcp.get("summary"), dict) else {}
    servers = summary.get("servers") or []
    identifiers: list[str] = []
    if isinstance(servers, list):
        for item in servers:
            if isinstance(item, dict):
                value = item.get("server_id") or item.get("address")
            else:
                value = item
            if value and str(value) not in identifiers:
                identifiers.append(str(value))
    return identifiers
