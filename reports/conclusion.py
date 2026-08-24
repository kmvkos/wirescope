"""Deterministic Russian executive conclusion from persisted audit data.

Templates and counts only. No LLM, no new scans, no invented CVEs.
"""

from __future__ import annotations

from findings.models import FindingStatus, Severity
from reports.models import (
    CONCLUSION_SCHEMA,
    CONCLUSION_SCHEMA_VERSION,
    MAX_SUMMARY,
    ReportFinding,
    ReportPassive,
    ReportSource,
)


NMAP_ARTIFACTS = frozenset({"nmap_xml", "active_discovery_result"})
PROTOCOL_ARTIFACTS = frozenset({"protocol_audit_result"})
FINDINGS_ARTIFACTS = frozenset({"findings_result"})

_SEVERITY_ORDER = (
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
)

_SEVERITY_RU = {
    "critical": "критические",
    "high": "высокие",
    "medium": "средние",
    "low": "низкие",
    "info": "информационные",
}

_NOTABLE_RULES = (
    ("WS-MGMT-INSECURE-PROTOCOL", "небезопасное управление (Telnet/FTP и аналоги)"),
    ("WS-SMB-NULL-SESSION", "нулевая сессия SMB"),
    ("WS-SMB-LEGACY-DIALECT", "устаревший диалект SMB"),
    ("WS-SMB-SIGNING-DISABLED", "подпись SMB не обязательна"),
    ("WS-INFRA-LLMNR", "LLMNR"),
    ("WS-INFRA-NBNS", "NBNS/NetBIOS"),
    ("WS-LDAP-ANONYMOUS-BIND", "анонимный bind LDAP"),
    ("WS-SNMP-UNAUTHENTICATED", "SNMP без аутентификации"),
    ("WS-DNS-RECURSION", "рекурсивный DNS"),
    ("WS-TLS-LEGACY-PROTOCOL", "устаревший TLS"),
    ("WS-TLS-WEAK-CIPHER", "слабый шифр TLS"),
    ("WS-SSH-WEAK-ALGORITHMS", "слабые алгоритмы SSH"),
    ("WS-INFRA-MULTIPLE-DHCP", "несколько DHCP-серверов"),
)

VLAN_CAVEAT = (
    "VLAN в кадре виден только при 802.1Q; access-порт коммутатора часто "
    "без тега — тогда ID неизвестен, но трафик этой сети всё равно виден."
)

_EMPTY_NOT_CLEAR = (
    "Пустой список протокольных находок при видимых хостах — это не "
    "«всё чисто»: инвентарь без найденных слабых протоколов не доказывает "
    "отсутствие риска."
)


def build_executive_conclusion(
    source: ReportSource,
    passive: ReportPassive,
    *,
    open_findings: list[ReportFinding] | None = None,
    by_severity: dict[str, int] | None = None,
) -> dict[str, str | int]:
    findings = list(open_findings) if open_findings is not None else [
        item for item in source.findings if item.status == FindingStatus.OPEN.value
    ]
    counts = by_severity or _open_severity_counts(findings)
    nmap_ran, protocol_ran, findings_ran = _stage_flags(source)
    paragraphs = [
        _posture_paragraph(source, passive),
        _severity_paragraph(counts, findings),
        _exposures_paragraph(findings),
        _caveats_paragraph(
            source,
            passive,
            finding_count=len(source.findings),
            nmap_ran=nmap_ran,
            protocol_ran=protocol_ran,
            findings_ran=findings_ran,
        ),
    ]
    summary = "\n\n".join(item for item in paragraphs if item).strip()
    if len(summary) > MAX_SUMMARY:
        summary = summary[: MAX_SUMMARY - 1].rstrip() + "…"
    return {
        "schema": CONCLUSION_SCHEMA,
        "schema_version": CONCLUSION_SCHEMA_VERSION,
        "summary": summary,
    }


def _open_severity_counts(findings: list[ReportFinding]) -> dict[str, int]:
    counts = {name: 0 for name in _SEVERITY_ORDER}
    counts["info"] = 0
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts


def _posture_paragraph(source: ReportSource, passive: ReportPassive) -> str:
    status = passive.segment_status
    vlans = list(passive.tagged_vlan_ids)
    hosts = max(len(source.assets), passive.arp_host_count)
    host_text = _hosts_phrase(hosts)
    if status == "quiet":
        posture = "Сегмент тихий: кадров не зафиксировано"
    elif status == "tagged_vlans" and vlans:
        posture = f"Найдены VLAN {_format_vlans(vlans)}"
        if passive.untagged_traffic_observed:
            posture = (
                f"Виден нетегированный трафик; найдены VLAN {_format_vlans(vlans)}"
            )
    elif status == "untagged_traffic":
        posture = "Виден нетегированный трафик; ID VLAN неизвестен"
        if vlans:
            posture = (
                f"Виден нетегированный трафик; найдены VLAN {_format_vlans(vlans)}"
            )
    elif status == "very_low":
        frames = passive.frame_count if passive.frame_count is not None else 0
        posture = f"Очень мало трафика ({frames} кадров)"
    elif status == "active":
        posture = "Наблюдался сетевой трафик"
        if vlans:
            posture = f"{posture}; найдены VLAN {_format_vlans(vlans)}"
    elif not passive.available:
        posture = "Пассивный захват для этого аудита не сохранён"
    else:
        posture = "Состояние сегмента по пассивному захвату не определено"
    return f"{posture}. {host_text}."


def _hosts_phrase(count: int) -> str:
    if count == 0:
        return "Активных хостов не зафиксировано"
    return f"Зафиксировано {_ru_count(count, 'активный хост', 'активных хоста', 'активных хостов')}"


def _severity_paragraph(
    counts: dict[str, int],
    findings: list[ReportFinding],
) -> str:
    open_total = sum(counts.get(name, 0) for name in _SEVERITY_ORDER)
    parts = []
    for name in _SEVERITY_ORDER:
        total = counts.get(name, 0)
        if total:
            parts.append(f"{_SEVERITY_RU[name]} — {total}")
    if not findings:
        return (
            "Открытых находок нет (критические — 0, высокие — 0, "
            "средние — 0, низкие — 0)."
        )
    listed = ", ".join(parts) if parts else "по критическим/высоким/средним/низким — 0"
    return (
        f"Открытых находок: {open_total}. По серьёзности: {listed}."
    )


def _exposures_paragraph(findings: list[ReportFinding]) -> str:
    if not findings:
        return ""
    labels: list[str] = []
    seen: set[str] = set()
    management = _management_labels(findings)
    if management:
        labels.append(management)
        seen.add("WS-MGMT-INSECURE-PROTOCOL")
    for rule_id, label in _NOTABLE_RULES:
        if rule_id in seen:
            continue
        if any(item.rule_id == rule_id for item in findings):
            labels.append(label)
            seen.add(rule_id)
    if not labels:
        titles = []
        for item in findings:
            if item.title not in titles:
                titles.append(item.title)
            if len(titles) >= 4:
                break
        labels = titles
    return f"Заметные экспозиции: {', '.join(labels)}."


_MGMT_LABELS = {
    "telnet": "Telnet",
    "ftp": "FTP",
    "tftp": "TFTP",
    "rsh": "rsh",
    "rlogin": "rlogin",
    "rexec": "rexec",
}


def _management_labels(findings: list[ReportFinding]) -> str | None:
    names: list[str] = []
    for item in findings:
        if item.rule_id != "WS-MGMT-INSECURE-PROTOCOL":
            continue
        matched = str((item.data or {}).get("matched_as") or "").strip().lower()
        token = _MGMT_LABELS.get(matched, matched)
        if token and token not in names:
            names.append(token)
    if not names:
        return None
    return "/".join(names)


def _caveats_paragraph(
    source: ReportSource,
    passive: ReportPassive,
    *,
    finding_count: int,
    nmap_ran: bool,
    protocol_ran: bool,
    findings_ran: bool,
) -> str:
    bits: list[str] = []
    hosts = max(len(source.assets), passive.arp_host_count)
    if finding_count == 0 and hosts > 0:
        bits.append(_EMPTY_NOT_CLEAR)
        if not findings_ran:
            bits.append("Оценка находок не выполнялась.")
        elif not protocol_ran:
            bits.append(
                "Протокольный аудит не запускался, поэтому отсутствие "
                "находок не означает безопасную конфигурацию служб."
            )
    no_l3 = passive.had_l3_address is False
    no_dhcp = not passive.dhcp.observed
    if no_l3:
        if no_dhcp:
            bits.append(
                "На NIC захвата нет L3-адреса, DHCP не наблюдался. " + VLAN_CAVEAT
            )
        else:
            bits.append("На NIC захвата нет L3-адреса. " + VLAN_CAVEAT)
    elif no_dhcp and passive.available:
        bits.append("DHCP на сегменте не наблюдался. " + VLAN_CAVEAT)
    if not nmap_ran:
        bits.append("Nmap не запускался.")
    return " ".join(bits)


def _stage_flags(source: ReportSource) -> tuple[bool, bool, bool]:
    types = {item.artifact_type for item in source.evidence_references}
    nmap = bool(types & NMAP_ARTIFACTS)
    protocol = bool(types & PROTOCOL_ARTIFACTS)
    findings = bool(types & FINDINGS_ARTIFACTS) or bool(source.findings)
    if source.audit_profile == "passive":
        nmap = False
    return nmap, protocol, findings


def _format_vlans(vlan_ids: list[int]) -> str:
    shown = [str(item) for item in vlan_ids[:8]]
    if len(vlan_ids) > 8:
        shown.append("…")
    return ", ".join(shown)


def _ru_count(n: int, one: str, few: str, many: str) -> str:
    n_abs = abs(n) % 100
    if 11 <= n_abs <= 14:
        word = many
    else:
        rem = n_abs % 10
        if rem == 1:
            word = one
        elif rem in {2, 3, 4}:
            word = few
        else:
            word = many
    return f"{n} {word}"


__all__ = [
    "FINDINGS_ARTIFACTS",
    "NMAP_ARTIFACTS",
    "PROTOCOL_ARTIFACTS",
    "VLAN_CAVEAT",
    "build_executive_conclusion",
]
