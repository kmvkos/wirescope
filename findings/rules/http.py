"""HTTP security-configuration findings from http_response observations."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import HTTPS_NAMES, HTTPS_PORTS
from findings.copy import (
    HTTP_MISSING_HEADERS,
    HTTP_MISSING_HSTS,
    HTTP_SERVER_DISCLOSURE,
    http_disclosure_rationale,
    http_headers_rationale,
    http_hsts_rationale,
)
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    service_map,
    usable_observations,
)
from inventory.models import ServiceRecord
from protocol_audits.models import ProtocolObservationRecord


class MissingHstsRule:
    id = "WS-HTTP-MISSING-HSTS"
    version = "1"
    family = "http"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        services = service_map(context)
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"http_response"})
        ).values():
            sample = group[0]
            service = services.get(sample.service_id)
            if service is None or not _is_https(service):
                continue
            if any(_header(item, "strict-transport-security") for item in group):
                continue
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=HTTP_MISSING_HSTS["title"],
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=HTTP_MISSING_HSTS["description"],
                    rationale=http_hsts_rationale(),
                    recommendation=HTTP_MISSING_HSTS["recommendation"],
                    data={"headers": _headers(sample)},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class MissingSecurityHeadersRule:
    id = "WS-HTTP-MISSING-SECURITY-HEADERS"
    version = "1"
    family = "http"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"http_response"})
        ).values():
            missing: list[str] = []
            if not any(_header(item, "x-frame-options") for item in group) and not any(
                "frame-ancestors" in (_header(item, "content-security-policy") or "")
                for item in group
            ):
                missing.append("x-frame-options")
            if not any(_header(item, "content-security-policy") for item in group):
                missing.append("content-security-policy")
            if not missing:
                continue
            sample = group[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=HTTP_MISSING_HEADERS["title"],
                    severity=Severity.LOW,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=HTTP_MISSING_HEADERS["description"],
                    rationale=http_headers_rationale(", ".join(missing)),
                    recommendation=HTTP_MISSING_HEADERS["recommendation"],
                    data={"missing_headers": missing, "headers": _headers(sample)},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class HttpServerDisclosureRule:
    id = "WS-HTTP-SERVER-DISCLOSURE"
    version = "1"
    family = "http"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"http_response"})
        ).values():
            disclosed = {}
            for item in group:
                headers = _headers(item)
                for name in ("server", "x-powered-by"):
                    if headers.get(name):
                        disclosed[name] = headers[name]
            if not disclosed:
                continue
            sample = group[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=HTTP_SERVER_DISCLOSURE["title"],
                    severity=Severity.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=HTTP_SERVER_DISCLOSURE["description"],
                    rationale=http_disclosure_rationale(
                        ", ".join(
                            f"{key}={value}" for key, value in disclosed.items()
                        )
                    ),
                    recommendation=HTTP_SERVER_DISCLOSURE["recommendation"],
                    data={"headers": disclosed},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


def _is_https(service: ServiceRecord) -> bool:
    if (service.tunnel or "").lower() == "ssl":
        return True
    name = (service.service_name or "").lower()
    if name in HTTPS_NAMES:
        return True
    return service.port in HTTPS_PORTS


def _headers(item: ProtocolObservationRecord) -> dict[str, str]:
    raw = item.data.get("headers") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items() if value}


def _header(item: ProtocolObservationRecord, name: str) -> str | None:
    value = _headers(item).get(name.lower())
    return value or None
