"""Product-coherence policy for Traffic Analysis observations.

Traffic Analysis owns facts visible in one capture window and network diagnostics.
It does not own security findings or remediation for services discovered by an
audit.  This module keeps the persisted traffic contract backward-compatible
while neutralising legacy protocol-presence observations before the operator
summary is calculated.
"""

from __future__ import annotations

from typing import Any


_PROTOCOL_VISIBILITY = {
    "Обнаружен Telnet": "Telnet",
    "Обнаружен FTP": "FTP",
    "Наблюдался обычный HTTP": "HTTP",
    "Наблюдался LLMNR": "LLMNR",
    "Наблюдался NBNS/NetBIOS Name Service": "NBNS",
}


def apply_product_coherence(document: dict[str, Any]) -> dict[str, Any]:
    """Keep protocol presence as PCAP evidence, not a security assessment.

    Older analyzer rules emitted legacy-protocol presence with ``category=security``
    and warning severity.  That blurred the boundary with Audit Findings and made
    a PCAP report look like a second vulnerability report.  The raw observation
    shape remains compatible, but its interpretation becomes capture context.
    """

    observations = document.get("observations")
    if not isinstance(observations, list):
        return document

    for row in observations:
        if not isinstance(row, dict):
            continue
        title = str(row.get("title") or "")
        protocol = _PROTOCOL_VISIBILITY.get(title)
        if protocol is None or str(row.get("category") or "") != "security":
            continue

        row["severity"] = "info"
        row["category"] = "protocol_visibility"
        row["meaning"] = (
            f"{protocol} присутствовал в выбранном PCAP. Traffic Analysis фиксирует "
            "наблюдаемый протокол, но сам по себе не создаёт security finding и не "
            "определяет, является ли соответствующий сервис допустимым."
        )
        row["check"] = (
            "Если нужен security-контекст, используйте Findings/Audit Report. "
            "При наличии подходящего аудита «Корреляция результатов» может показать, "
            "связан ли наблюдаемый traffic с обнаруженным inventory service."
        )
        row["assessment_owner"] = "audit_report"

    return document


__all__ = ["apply_product_coherence"]
