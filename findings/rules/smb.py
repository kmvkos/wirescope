"""SMB null-session, signing, and dialect findings."""

from engine.passive_models import ConfidenceLevel
from findings.catalog import LEGACY_SMB_DIALECTS, SMB_SIGNING_DISABLED
from findings.copy import (
    SMB_LEGACY,
    SMB_NULL_SESSION,
    SMB_SIGNING,
    smb_dialect_rationale,
    smb_null_rationale,
    smb_signing_rationale,
)
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
                    title=SMB_NULL_SESSION["title"],
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=SMB_NULL_SESSION["description"],
                    rationale=smb_null_rationale(sample.data.get("share_count")),
                    recommendation=SMB_NULL_SESSION["recommendation"],
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
                    title=SMB_SIGNING["title"],
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=SMB_SIGNING["description"],
                    rationale=smb_signing_rationale(),
                    recommendation=SMB_SIGNING["recommendation"],
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
                    title=SMB_LEGACY["title"],
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    asset_id=sample.asset_id,
                    service_id=sample.service_id,
                    description=SMB_LEGACY["description"],
                    rationale=smb_dialect_rationale(dialect),
                    recommendation=SMB_LEGACY["recommendation"],
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
