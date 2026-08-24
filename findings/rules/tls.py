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
                    title="Legacy TLS protocol is negotiated",
                    severity=_protocol_severity(legacy),
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The TLS handshake negotiated a protocol older than "
                        "TLS 1.2."
                    ),
                    rationale=(
                        "tls_session observations recorded protocol "
                        f"{legacy[0]}."
                    ),
                    recommendation=(
                        "Disable SSLv3, TLS 1.0, and TLS 1.1. Offer TLS 1.2 "
                        "and TLS 1.3 only."
                    ),
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
                    title="Weak TLS cipher is negotiated",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The TLS handshake selected a cipher suite that uses "
                        "NULL, EXPORT, RC4, DES, 3DES, MD5, or anonymous DH."
                    ),
                    rationale=(
                        "tls_session observations recorded cipher "
                        f"{weak[0]}."
                    ),
                    recommendation=(
                        "Disable legacy cipher suites and prefer AEAD suites "
                        "such as AES-GCM or ChaCha20-Poly1305."
                    ),
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
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "The presented TLS certificate notAfter date is in "
                        "the past relative to evaluation time."
                    ),
                    rationale=(
                        "tls_certificate.not_after is "
                        f"{sample.data.get('not_after')} and evaluation time "
                        f"is {context.evaluated_at.isoformat()}."
                    ),
                    recommendation=(
                        "Replace the certificate before expiry and automate "
                        "renewal."
                    ),
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
                    title="TLS certificate did not verify",
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "OpenSSL reported a non-zero certificate verify code "
                        "for this service."
                    ),
                    rationale=(
                        "tls_certificate.verify_code is "
                        f"{sample.data.get('verify_code')} "
                        f"({sample.data.get('verify_message')})."
                    ),
                    recommendation=(
                        "Install a certificate issued by a trusted CA, or "
                        "document the private PKI if this is an expected "
                        "lab/internal trust anchor."
                    ),
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
