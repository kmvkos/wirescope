"""SMB null-session, signing, and dialect findings."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import LEGACY_SMB_DIALECTS, SMB_SIGNING_DISABLED
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.rules.base import (
    draft,
    grouped_by_service,
    service_dedupe_key,
    usable_observations,
)


class SmbNullSessionRule:
    id = "WS-SMB-NULL-SESSION"
    version = "1"
    family = "smb"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for group in grouped_by_service(
            usable_observations(context, {"smb_null_session"})
        ).values():
            accepted = [item for item in group if item.data.get("accepted") is True]
            if not accepted:
                continue
            sample = accepted[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title="SMB null session was accepted",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "Unauthenticated SMB listing succeeded against this "
                        "service."
                    ),
                    rationale=(
                        "smb_null_session.accepted is true"
                        + (
                            f" with {sample.data.get('share_count')} shares"
                            if sample.data.get("share_count") is not None
                            else ""
                        )
                        + "."
                    ),
                    recommendation=(
                        "Disable anonymous/null SMB sessions and restrict "
                        "share listing to authenticated users."
                    ),
                    data={
                        "accepted": True,
                        "share_count": sample.data.get("share_count"),
                        "shares": sample.data.get("shares") or [],
                    },
                    observations=accepted,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class SmbSigningDisabledRule:
    id = "WS-SMB-SIGNING-DISABLED"
    version = "1"
    family = "smb"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        kinds = {"smb_null_session", "smb_probe_result"}
        for group in grouped_by_service(usable_observations(context, kinds)).values():
            disabled = [item for item in group if _signing_disabled(item.data)]
            if not disabled:
                continue
            sample = disabled[0]
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title="SMB signing is not required",
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=(
                        "Normalized SMB observations report signing disabled "
                        "or not required."
                    ),
                    rationale="smb signing field indicates signing is off.",
                    recommendation="Require SMB signing on this service.",
                    data={"signing": _signing_value(sample.data)},
                    observations=disabled,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


class SmbLegacyDialectRule:
    id = "WS-SMB-LEGACY-DIALECT"
    version = "1"
    family = "smb"

    def evaluate(self, context: EvaluationContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        kinds = {"smb_null_session", "smb_probe_result"}
        for group in grouped_by_service(usable_observations(context, kinds)).values():
            legacy = [item for item in group if _legacy_dialect(item.data)]
            if not legacy:
                continue
            sample = legacy[0]
            dialect = _dialect_value(sample.data)
            findings.append(
                draft(
                    rule_id=self.id,
                    rule_version=self.version,
                    family=self.family,
                    title="Legacy SMB dialect is offered",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description="The service appears to offer SMBv1 or LANMAN.",
                    rationale=f"Normalized dialect field is {dialect}.",
                    recommendation="Disable SMBv1 and other legacy dialects.",
                    data={"dialect": dialect},
                    observations=legacy,
                    dedupe_key=service_dedupe_key(sample),
                )
            )
        return findings


def _signing_value(data: dict) -> object:
    return data.get("signing") or data.get("smb_signing")


def _signing_disabled(data: dict) -> bool:
    value = _signing_value(data)
    if isinstance(value, bool):
        return value is False
    if value is None:
        return False
    return str(value).strip().lower() in SMB_SIGNING_DISABLED


def _dialect_value(data: dict) -> str | None:
    value = data.get("dialect") or data.get("smb_dialect")
    return str(value) if value else None


def _legacy_dialect(data: dict) -> bool:
    dialect = _dialect_value(data)
    if not dialect:
        return False
    return dialect.strip().lower() in LEGACY_SMB_DIALECTS
