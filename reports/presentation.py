"""Human-facing Russian presentation helpers for report exports.

Canonical audit-report values remain stable machine tokens. These helpers only
localize presentation and therefore do not affect source_hash or report schema.
"""

from __future__ import annotations

from reports.models import AuditReport


_HEADLINES = {
    "Open critical findings require attention": (
        "Есть критические проблемы — разберите их в первую очередь"
    ),
    "Open high-severity findings were identified": (
        "Есть проблемы высокой важности"
    ),
    "Open medium-severity findings were identified": (
        "Есть проблемы средней важности"
    ),
    "Open findings were recorded": "Зафиксированы проблемы безопасности",
    "No open findings were recorded for the confirmed scope": (
        "В подтверждённом scope открытых проблем не зафиксировано"
    ),
    "No open findings were recorded": "Открытых проблем не зафиксировано",
    "Capture completed with no frames": "Захват завершён: кадров нет",
    "Untagged traffic was observed; VLAN ID is unknown": (
        "Наблюдался нетегированный трафик; ID VLAN неизвестен"
    ),
    "Passive observations were recorded": "Зафиксированы пассивные наблюдения",
    "No hosts, services, or findings were recorded": (
        "Устройства, службы и проблемы не зафиксированы"
    ),
}


def human_headline(value: str | None) -> str:
    if not value:
        return "Итог аудита"
    if value in _HEADLINES:
        return _HEADLINES[value]
    prefix = "Saw tagged VLANs "
    if value.startswith(prefix):
        return f"В кадрах обнаружены тегированные VLAN {value[len(prefix):]}"
    return value


def localized_report(report: AuditReport) -> AuditReport:
    """Return a presentation-only copy with a localized headline."""
    summary = report.executive_summary.model_copy(
        update={"headline": human_headline(report.executive_summary.headline)}
    )
    return report.model_copy(update={"executive_summary": summary})


__all__ = ["human_headline", "localized_report"]
