"""HTTP security-configuration findings from http_response observations."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import HTTPS_NAMES, HTTPS_PORTS
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
                    title="HTTPS service does not send HSTS",
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The HTTPS response omitted "
                        "Strict-Transport-Security."
                    ),
                    rationale=(
                        "http_response headers were normalized and did not "
                        "include strict-transport-security on an HTTPS "
                        "service."
                    ),
                    recommendation=(
                        "Send Strict-Transport-Security with a conservative "
                        "max-age on HTTPS listeners. Do not enable HSTS on "
                        "plain HTTP."
                    ),
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
                    title="HTTP security headers are incomplete",
                    severity=Severity.LOW,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The HTTP response omitted common click-jacking or "
                        "content-security headers."
                    ),
                    rationale=(
                        "http_response headers did not include: "
                        + ", ".join(missing)
                    ),
                    recommendation=(
                        "Add Content-Security-Policy and either "
                        "X-Frame-Options or CSP frame-ancestors."
                    ),
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
                    title="HTTP server identity is disclosed",
                    severity=Severity.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The HTTP response includes Server or X-Powered-By."
                    ),
                    rationale=(
                        "http_response headers recorded "
                        + ", ".join(f"{key}={value}" for key, value in disclosed.items())
                    ),
                    recommendation=(
                        "Omit or genericize Server and X-Powered-By unless "
                        "needed for compatibility."
                    ),
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
