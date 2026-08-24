"""TLS protocol, cipher, and certificate findings."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from engine.passive_models import ConfidenceLevel
from findings.catalog import (
    LEGACY_TLS_PROTOCOLS,
    SSL_TOKENS,
    TLS1_0_TOKENS,
    WEAK_TLS_CIPHER_TOKENS,
)
from findings.copy import (
    TLS_CERT_EXPIRED,
    TLS_CERT_UNTRUSTED,
    TLS_LEGACY,
    TLS_WEAK_CIPHER,
    tls_cipher_rationale,
    tls_expired_rationale,
    tls_legacy_rationale,
    tls_untrusted_rationale,
)
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)
from protocol_audits.models import ProtocolObservationRecord


class LegacyTlsProtocolRule:
    id = "WS-TLS-LEGACY-PROTOCOL"
    version = "1"
    family = "tls"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"tls_session"})
        ).values():
            protocols = [
                str(item.data.get("protocol") or "")
                for item in group
                if item.data.get("protocol")
            ]
            legacy = [
                protocol
                for protocol in protocols
                if _normalize_protocol(protocol) in LEGACY_TLS_PROTOCOLS
            ]
            if not legacy:
                continue
            sample = group[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=TLS_LEGACY["title"],
                    severity=_protocol_severity(legacy),
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=TLS_LEGACY["description"],
                    rationale=tls_legacy_rationale(legacy[0]),
                    recommendation=TLS_LEGACY["recommendation"],
                    data={"protocols": legacy},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class WeakTlsCipherRule:
    id = "WS-TLS-WEAK-CIPHER"
    version = "1"
    family = "tls"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"tls_session"})
        ).values():
            weak = [
                str(item.data.get("cipher"))
                for item in group
                if item.data.get("cipher") and _weak_cipher(str(item.data["cipher"]))
            ]
            if not weak:
                continue
            sample = group[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=TLS_WEAK_CIPHER["title"],
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=TLS_WEAK_CIPHER["description"],
                    rationale=tls_cipher_rationale(weak[0]),
                    recommendation=TLS_WEAK_CIPHER["recommendation"],
                    data={"ciphers": weak},
                    observations=group,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class TlsCertificateExpiredRule:
    id = "WS-TLS-CERT-EXPIRED"
    version = "1"
    family = "tls"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"tls_certificate"})
        ).values():
            expired = [
                item
                for item in group
                if _expired(item.data.get("not_after"), context.evaluated_at)
            ]
            if not expired:
                continue
            sample = expired[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=TLS_CERT_EXPIRED["title"],
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=TLS_CERT_EXPIRED["description"],
                    rationale=tls_expired_rationale(
                        sample.data.get("not_after"),
                        context.evaluated_at.isoformat(),
                    ),
                    recommendation=TLS_CERT_EXPIRED["recommendation"],
                    data={
                        "not_after": sample.data.get("not_after"),
                        "subject": sample.data.get("subject"),
                    },
                    observations=expired,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class TlsCertificateUntrustedRule:
    id = "WS-TLS-CERT-UNTRUSTED"
    version = "1"
    family = "tls"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"tls_certificate"})
        ).values():
            untrusted = [
                item
                for item in group
                if _untrusted(item)
            ]
            if not untrusted:
                continue
            sample = untrusted[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title=TLS_CERT_UNTRUSTED["title"],
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=TLS_CERT_UNTRUSTED["description"],
                    rationale=tls_untrusted_rationale(
                        sample.data.get("verify_code"),
                        sample.data.get("verify_message"),
                    ),
                    recommendation=TLS_CERT_UNTRUSTED["recommendation"],
                    data={
                        "verify_code": sample.data.get("verify_code"),
                        "verify_message": sample.data.get("verify_message"),
                        "subject": sample.data.get("subject"),
                        "issuer": sample.data.get("issuer"),
                    },
                    observations=untrusted,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


def _normalize_protocol(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace(" ", "")
        .replace("_", "")
    )


def _protocol_severity(protocols: list[str]) -> Severity:
    tokens = {_normalize_protocol(item) for item in protocols}
    if tokens & SSL_TOKENS:
        return Severity.CRITICAL
    if tokens & TLS1_0_TOKENS:
        return Severity.HIGH
    return Severity.MEDIUM


def _weak_cipher(cipher: str) -> bool:
    upper = cipher.upper()
    return any(token in upper for token in WEAK_TLS_CIPHER_TOKENS)


def _expired(not_after: object, evaluated_at: datetime) -> bool:
    parsed = _parse_time(not_after)
    if parsed is None:
        return False
    return parsed < evaluated_at


def _untrusted(item: ProtocolObservationRecord) -> bool:
    code = item.data.get("verify_code")
    if code is None:
        return False
    try:
        return int(code) != 0
    except (TypeError, ValueError):
        return False


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = " ".join(value.strip().split())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(normalized, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    try:
        parsed = parsedate_to_datetime(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError, IndexError):
        return None
