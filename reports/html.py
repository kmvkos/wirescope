"""Self-contained HTML renderer for the audit-report view model.

Every interpolated value is HTML-escaped. Raw provider output is never
included. The document carries inline CSS so it can be opened offline.
"""

from __future__ import annotations

import html
import json
from typing import Any

from reports.models import (
    AuditReport,
    ReportAsset,
    ReportEvidenceReference,
    ReportFinding,
    ReportRecommendation,
    ReportService,
)


def render_html(report: AuditReport) -> str:
    document = report.to_document()
    summary = report.executive_summary
    generated = _t(document["generated_at"])
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>WireScope report {_t(report.audit.id)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<header class="hero">\n'
        "<p class=\"eyebrow\">WireScope audit report</p>\n"
        f"<h1>{_t(summary.headline)}</h1>\n"
        "<p class=\"meta\">"
        f"Audit {_t(report.audit.id)} · generated {generated} · "
        f"schema {_t(report.schema_name)} v{_t(report.schema_version)}"
        "</p>\n"
        "</header>\n"
        f"{_summary_section(report)}"
        f"{_environment_section(report)}"
        f"{_scope_section(report)}"
        f"{_assets_section(report.assets)}"
        f"{_services_section(report.services)}"
        f"{_findings_section(report.findings)}"
        f"{_recommendations_section(report.recommendations)}"
        f"{_evidence_section(report.evidence_references)}"
        f"{_metadata_section(report)}"
        "</body>\n"
        "</html>\n"
    )


def _summary_section(report: AuditReport) -> str:
    summary = report.executive_summary
    severity_cells = "".join(
        (
            "<div class=\"stat\">"
            f"<span class=\"label\">{_t(name)}</span>"
            f"<span class=\"value severity-{_t(name)}\">{_t(total)}</span>"
            "</div>"
        )
        for name, total in summary.by_severity.items()
    )
    sensors = (
        ", ".join(_t(name) for name in summary.detected_sensors)
        if summary.detected_sensors
        else "none recorded"
    )
    return (
        '<section id="executive-summary">\n'
        "<h2>Executive summary</h2>\n"
        '<div class="stats">\n'
        f"<div class=\"stat\"><span class=\"label\">Assets</span>"
        f"<span class=\"value\">{_t(summary.asset_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">Services</span>"
        f"<span class=\"value\">{_t(summary.service_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">Findings</span>"
        f"<span class=\"value\">{_t(summary.finding_count)}</span></div>\n"
        f"<div class=\"stat\"><span class=\"label\">Open</span>"
        f"<span class=\"value\">{_t(summary.open_finding_count)}</span></div>\n"
        "</div>\n"
        f'<div class="stats">{severity_cells}</div>\n'
        "<p>Confirmed scope: "
        f"{'yes' if summary.confirmed_scope else 'no'}. "
        f"Detected passive sensors: {sensors}.</p>\n"
        "</section>\n"
    )


def _environment_section(report: AuditReport) -> str:
    env = report.environment
    rows = []
    for iface in env.interfaces:
        addresses = ", ".join(_t(item) for item in [*iface.ipv4, *iface.ipv6])
        rows.append(
            "<tr>"
            f"<td>{_t(iface.name)}</td>"
            f"<td>{_t(iface.state)}</td>"
            f"<td>{_t(iface.mac)}</td>"
            f"<td>{addresses or '—'}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Interface</th><th>State</th>"
        "<th>MAC</th><th>Addresses</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else "<p>No interface snapshot was stored.</p>"
    )
    route = env.default_route or {}
    route_text = (
        f"gateway {_t(route.get('gateway'))} via {_t(route.get('interface'))}"
        if route
        else "not recorded"
    )
    dns = ", ".join(_t(item) for item in env.dns) or "not recorded"
    return (
        '<section id="environment">\n'
        "<h2>Environment</h2>\n"
        f"<p>Hostname: {_t(env.hostname) or 'not recorded'}. "
        f"Default route: {route_text}. DNS: {dns}.</p>\n"
        f"{table}\n"
        "</section>\n"
    )


def _scope_section(report: AuditReport) -> str:
    scope = report.scope
    targets = ", ".join(_t(item) for item in scope.targets) or "none"
    audit_scope = _json_block(scope.audit_scope)
    return (
        '<section id="scope">\n'
        "<h2>Scope</h2>\n"
        "<p>"
        f"Confirmed: {'yes' if scope.confirmed else 'no'}. "
        f"Profile: {_t(scope.profile) or '—'}. "
        f"Interface: {_t(scope.interface) or '—'}. "
        f"Address count: {_t(scope.address_count) if scope.address_count is not None else '—'}. "
        f"Timing: {_t(scope.timing_policy) or '—'}."
        "</p>\n"
        f"<p>Targets: {targets}.</p>\n"
        "<h3>Audit scope snapshot</h3>\n"
        f"{audit_scope}\n"
        "</section>\n"
    )


def _assets_section(assets: list[ReportAsset]) -> str:
    if not assets:
        body = "<p>No assets were persisted for this audit.</p>"
    else:
        rows = []
        for asset in assets:
            rows.append(
                "<tr>"
                f"<td>{_t(asset.id)}</td>"
                f"<td>{_t(asset.state)}</td>"
                f"<td>{_t(asset.mac)}</td>"
                f"<td>{_t(asset.vendor)}</td>"
                f"<td>{_t(', '.join(asset.addresses))}</td>"
                f"<td>{_t(', '.join(asset.names))}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>ID</th><th>State</th><th>MAC</th>"
            "<th>Vendor</th><th>Addresses</th><th>Names</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="assets">\n'
        "<h2>Assets</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _services_section(services: list[ReportService]) -> str:
    if not services:
        body = "<p>No services were persisted for this audit.</p>"
    else:
        rows = []
        for service in services:
            product = " ".join(
                part
                for part in (service.product, service.version)
                if part
            )
            rows.append(
                "<tr>"
                f"<td>{_t(service.asset_id)}</td>"
                f"<td>{_t(service.protocol)}</td>"
                f"<td>{_t(service.port)}</td>"
                f"<td>{_t(service.state)}</td>"
                f"<td>{_t(service.service_name)}</td>"
                f"<td>{_t(product)}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>Asset</th><th>Proto</th><th>Port</th>"
            "<th>State</th><th>Service</th><th>Product</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="services">\n'
        "<h2>Services</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _findings_section(findings: list[ReportFinding]) -> str:
    if not findings:
        body = "<p>No findings were persisted for this audit.</p>"
    else:
        cards = []
        for item in findings:
            cards.append(
                f'<article class="finding severity-{_t(item.severity)}">'
                f"<h3>{_t(item.title)}</h3>"
                "<p class=\"meta\">"
                f"{_t(item.rule_id)} · {_t(item.severity)} · "
                f"{_t(item.status)} · confidence {_t(item.confidence)}"
                "</p>"
                f"<p>{_t(item.description)}</p>"
                f"<p><strong>Rationale.</strong> {_t(item.rationale)}</p>"
                "<p><strong>Recommendation.</strong> "
                f"{_t(item.recommendation)}</p>"
                "<p class=\"meta\">"
                f"Asset {_t(item.asset_id) or '—'} · "
                f"service {_t(item.service_id) or '—'} · "
                f"observations {len(item.observation_ids)} · "
                f"evidence {len(item.evidence_artifact_ids)}"
                "</p>"
                f"{_json_block(item.data) if item.data else ''}"
                "</article>"
            )
        body = "".join(cards)
    return (
        '<section id="findings">\n'
        "<h2>Findings</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _recommendations_section(
    recommendations: list[ReportRecommendation],
) -> str:
    if not recommendations:
        body = "<p>No open-finding recommendations were produced.</p>"
    else:
        items = []
        for item in recommendations:
            items.append(
                "<li>"
                f"<strong>{_t(item.title)}</strong> "
                f"({_t(item.rule_id)}, {_t(item.severity)}): "
                f"{_t(item.recommendation)} "
                f"— {_t(len(item.finding_ids))} finding(s)"
                "</li>"
            )
        body = "<ol>" + "".join(items) + "</ol>"
    return (
        '<section id="recommendations">\n'
        "<h2>Recommendations</h2>\n"
        f"{body}\n"
        "</section>\n"
    )


def _evidence_section(references: list[ReportEvidenceReference]) -> str:
    note = (
        "<p>Raw provider output remains in controlled evidence storage. "
        "This report lists identifiers, types, sizes, and SHA-256 hashes "
        "only.</p>"
    )
    if not references:
        body = "<p>No evidence artifacts were referenced.</p>"
    else:
        rows = []
        for item in references:
            rows.append(
                "<tr>"
                f"<td>{_t(item.id)}</td>"
                f"<td>{_t(item.artifact_type)}</td>"
                f"<td>{_t(item.content_type)}</td>"
                f"<td>{_t(item.size)}</td>"
                f"<td class=\"hash\">{_t(item.sha256)}</td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>ID</th><th>Type</th><th>Content type</th>"
            "<th>Size</th><th>SHA-256</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return (
        '<section id="evidence">\n'
        "<h2>Evidence references</h2>\n"
        f"{note}\n"
        f"{body}\n"
        "</section>\n"
    )


def _metadata_section(report: AuditReport) -> str:
    meta = report.metadata
    warnings = (
        "<ul>"
        + "".join(f"<li>{_t(item)}</li>" for item in meta.warnings)
        + "</ul>"
        if meta.warnings
        else "<p>None.</p>"
    )
    return (
        '<section id="audit-metadata">\n'
        "<h2>Audit metadata</h2>\n"
        "<ul>\n"
        f"<li>Product: {_t(meta.product)} {_t(meta.version)}</li>\n"
        f"<li>Report ID: {_t(report.report_id)}</li>\n"
        f"<li>Source hash: {_t(report.source_hash)}</li>\n"
        f"<li>Job ID: {_t(meta.job_id) or '—'}</li>\n"
        f"<li>Actor: {_t(meta.actor) or '—'}</li>\n"
        f"<li>Audit status: {_t(report.audit.status)}</li>\n"
        f"<li>Audit profile: {_t(report.audit.profile)}</li>\n"
        f"<li>Raw provider output excluded: "
        f"{'yes' if meta.raw_provider_output_excluded else 'no'}</li>\n"
        f"<li>Truncated: {'yes' if meta.truncated else 'no'}</li>\n"
        "</ul>\n"
        "<h3>Warnings</h3>\n"
        f"{warnings}\n"
        "</section>\n"
    )


def _json_block(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )
    return f"<pre>{_t(encoded)}</pre>"


def _t(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_CSS = """
:root { color-scheme: light; }
html { font-size: 16px; }
body {
  margin: 0 auto;
  max-width: 60rem;
  padding: 1rem;
  font-family: system-ui, sans-serif;
  line-height: 1.45;
  color: #1b1b1b;
  background: #f7f5f2;
}
.hero, section {
  background: #fff;
  border: 1px solid #d9d4cc;
  border-radius: 0.5rem;
  padding: 1rem;
  margin-bottom: 1rem;
}
h1, h2, h3 { line-height: 1.2; }
h1 { font-size: 1.6rem; margin: 0.2rem 0 0.6rem; }
h2 { font-size: 1.2rem; margin-top: 0; }
.eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.75rem; }
.meta { color: #4a4a4a; font-size: 0.9rem; }
.stats { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.75rem 0; }
.stat {
  min-width: 5.5rem;
  background: #f0ece6;
  border-radius: 0.4rem;
  padding: 0.5rem 0.7rem;
}
.stat .label { display: block; font-size: 0.75rem; color: #5c5c5c; }
.stat .value { font-size: 1.2rem; font-weight: 650; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { border-bottom: 1px solid #e6e1da; text-align: left; padding: 0.35rem; vertical-align: top; }
.hash, pre { overflow-wrap: anywhere; word-break: break-word; }
pre {
  background: #f4f1ec;
  padding: 0.6rem;
  border-radius: 0.35rem;
  font-size: 0.8rem;
}
.finding { border-left: 0.35rem solid #5d6d7e; padding-left: 0.7rem; margin: 0.8rem 0; }
.severity-critical, .finding.severity-critical { border-color: #8b1a1a; color: inherit; }
.severity-high, .finding.severity-high { border-color: #c0392b; }
.severity-medium, .finding.severity-medium { border-color: #d68910; }
.severity-low, .finding.severity-low { border-color: #1f618d; }
.stat .value.severity-critical { color: #8b1a1a; }
.stat .value.severity-high { color: #c0392b; }
@media (max-width: 40rem) {
  body { padding: 0.6rem; }
  table { display: block; overflow-x: auto; }
  h1 { font-size: 1.3rem; }
}
""".replace("\n", "")
