"""Markdown export for the canonical audit-report v1 document."""

from __future__ import annotations

from typing import Any


def _text(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(document: dict[str, Any]) -> str:
    audit = document.get("audit") or {}
    summary = document.get("executive_summary") or {}
    scope = document.get("scope") or {}
    passive = document.get("passive") or {}
    assets = document.get("assets") or []
    services = document.get("services") or []
    findings = document.get("findings") or []
    recommendations = document.get("recommendations") or []
    evidence = document.get("evidence_references") or []

    lines = [
        "# WireScope audit report",
        "",
        f"**Audit:** `{_text(audit.get('id'))}`  ",
        f"**Generated:** {_text(document.get('generated_at'))}  ",
        f"**Profile:** {_text(audit.get('profile'))}  ",
        f"**Interface:** {_text(audit.get('interface'))}  ",
        f"**Status:** {_text(audit.get('status'))}",
        "",
        "## Executive summary",
        "",
        f"**{_text(summary.get('headline'))}**",
        "",
        str(summary.get("summary") or "No executive summary is available."),
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Assets | {_text(summary.get('asset_count'))} |",
        f"| Services | {_text(summary.get('service_count'))} |",
        f"| Findings | {_text(summary.get('finding_count'))} |",
        f"| Open findings | {_text(summary.get('open_finding_count'))} |",
        f"| Highest open severity | {_text(summary.get('highest_open_severity'))} |",
        "",
        "## Scope",
        "",
        f"Confirmed: **{'yes' if scope.get('confirmed') else 'no'}**  ",
        f"Profile: {_text(scope.get('profile'))}  ",
        f"Interface: {_text(scope.get('interface'))}  ",
        f"Address count: {_text(scope.get('address_count'))}",
        "",
    ]
    targets = scope.get("targets") or []
    if targets:
        lines.extend(["Targets:", *[f"- `{_text(item)}`" for item in targets], ""])

    lines.extend(
        [
            "## Passive observations",
            "",
            f"Available: **{'yes' if passive.get('available') else 'no'}**  ",
            f"Frames: {_text(passive.get('frame_count'))}  ",
            f"Visibility: {_text(passive.get('visibility'))}  ",
            f"Segment: {_text(passive.get('segment_status'))}  ",
            f"VLANs: {_text(', '.join(str(x) for x in (passive.get('tagged_vlan_ids') or [])))}  ",
            f"ARP hosts: {_text(passive.get('arp_host_count'))}",
            "",
            "## Assets",
            "",
        ]
    )
    if assets:
        lines.extend([
            "| Address / name | MAC | Vendor | Class | OS |",
            "| --- | --- | --- | --- | --- |",
        ])
        for item in assets:
            labels = (item.get("names") or []) + (item.get("addresses") or [])
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(", ".join(labels[:4])),
                        _text(item.get("mac")),
                        _text(item.get("vendor")),
                        _text(item.get("device_class_hint")),
                        _text(item.get("os_name")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No assets were persisted.")
    lines.extend(["", "## Services", ""])
    if services:
        lines.extend([
            "| Asset | Proto | Port | Service | Product | State |",
            "| --- | --- | ---: | --- | --- | --- |",
        ])
        for item in services:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _text(item.get("asset_id")),
                        _text(item.get("protocol")),
                        _text(item.get("port")),
                        _text(item.get("service_name")),
                        _text(" ".join(x for x in [item.get("product"), item.get("version")] if x)),
                        _text(item.get("state")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No services were persisted.")

    lines.extend(["", "## Findings", ""])
    if findings:
        for item in findings:
            lines.extend(
                [
                    f"### [{_text(item.get('severity')).upper()}] {_text(item.get('title'))}",
                    "",
                    f"- Rule: `{_text(item.get('rule_id'))}`",
                    f"- Status: {_text(item.get('status'))}",
                    f"- Confidence: {_text(item.get('confidence'))}",
                    f"- Asset: `{_text(item.get('asset_id'))}`",
                    f"- Service: `{_text(item.get('service_id'))}`",
                    "",
                    _text(item.get("description")),
                    "",
                    f"**Why:** {_text(item.get('rationale'))}",
                    "",
                    f"**Recommendation:** {_text(item.get('recommendation'))}",
                    "",
                ]
            )
    else:
        lines.extend(["No findings were generated.", ""])

    lines.extend(["## Recommendations", ""])
    if recommendations:
        for item in recommendations:
            lines.extend(
                [
                    f"- **[{_text(item.get('severity')).upper()}] {_text(item.get('title'))}** — {_text(item.get('recommendation'))}",
                ]
            )
    else:
        lines.append("No recommendations were generated.")

    lines.extend(["", "## Evidence references", ""])
    if evidence:
        lines.extend([
            "| ID | Type | Content type | Size | SHA-256 |",
            "| --- | --- | --- | ---: | --- |",
        ])
        for item in evidence:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_text(item.get('id'))}`",
                        _text(item.get("artifact_type")),
                        _text(item.get("content_type")),
                        _text(item.get("size")),
                        f"`{_text(item.get('sha256'))}`",
                    ]
                )
                + " |"
            )
    else:
        lines.append("No evidence references were registered.")

    lines.extend(
        [
            "",
            "---",
            "Generated from persisted WireScope audit data. Raw provider output is referenced as evidence rather than embedded in this report.",
            "",
        ]
    )
    return "\n".join(lines)
