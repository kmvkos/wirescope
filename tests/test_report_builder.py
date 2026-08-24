from datetime import datetime, timezone
from pathlib import Path

import pytest

from reports.builder import build_audit_report, source_hash_for
from reports.html import render_html
from reports.models import (
    ReportAsset,
    ReportEvidenceReference,
    ReportFinding,
    ReportService,
    ReportSource,
)
from reports.validate import SchemaValidationError, validate_report_document


FROZEN = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "reports"
REPORT_ID = "00000000-0000-4000-8000-000000000001"


def sample_source(**overrides) -> ReportSource:
    payload = dict(
        audit_id="11111111-1111-4000-8000-111111111111",
        audit_status="running",
        audit_profile="standard",
        audit_interface="eth0",
        audit_actor="auditor",
        audit_created_at=FROZEN,
        audit_started_at=FROZEN,
        audit_finished_at=None,
        audit_summary={"schema": "findings-summary", "schema_version": 1},
        audit_scope={"site": "lab"},
        environment={
            "hostname": "wirescope-test",
            "interfaces": [
                {
                    "name": "eth0",
                    "state": "UP",
                    "mac": "00:11:22:33:44:55",
                    "ipv4": ["192.0.2.10/24"],
                    "ipv6": [],
                }
            ],
            "default_route": {"gateway": "192.0.2.1", "interface": "eth0"},
            "dns": ["192.0.2.53"],
        },
        confirmed_scope={
            "profile": "standard",
            "interface": "eth0",
            "targets": ["192.0.2.10"],
            "address_families": [4],
            "address_count": 1,
            "timing_policy": "T3",
            "snapshot_hash": "abc123",
        },
        assets=[
            ReportAsset(
                id="asset-1",
                state="responsive",
                mac="00:11:22:33:44:55",
                vendor="Example",
                device_class_hint="server-like",
                os_name="Linux",
                addresses=["192.0.2.10"],
                names=["linux.example.test"],
            )
        ],
        services=[
            ReportService(
                id="svc-1",
                asset_id="asset-1",
                protocol="tcp",
                port=22,
                state="open",
                service_name="ssh",
                product="OpenSSH",
                version="9.2",
                tunnel=None,
            )
        ],
        findings=[
            ReportFinding(
                id="finding-1",
                rule_id="WS-SSH-WEAK-ALGORITHMS",
                rule_version="1",
                family="ssh",
                title='Weak SSH <script>alert("xss")</script>',
                severity="high",
                confidence="high",
                status="open",
                asset_id="asset-1",
                service_id="svc-1",
                description="Weak algorithms were observed.",
                rationale="ssh_algorithms listed weak ciphers.",
                recommendation="Disable legacy algorithms.",
                observation_ids=["obs-1"],
                evidence_artifact_ids=["evidence-1"],
                data={"weak_algorithms": {"kex": ["diffie-hellman-group1-sha1"]}},
            )
        ],
        evidence_references=[
            ReportEvidenceReference(
                id="evidence-1",
                artifact_type="protocol_stdout",
                content_type="text/plain",
                size=12,
                sha256="a" * 64,
                schema_name=None,
                schema_version=None,
                created_at=FROZEN,
            )
        ],
        detected_sensors=["llmnr"],
        warnings=[],
        truncated=False,
    )
    payload.update(overrides)
    return ReportSource(**payload)


def sample_report(**overrides):
    return build_audit_report(
        sample_source(**overrides),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
        job_id="22222222-2222-4000-8000-222222222222",
        actor="auditor",
    )


def test_report_document_validates_against_published_schema():
    document = sample_report().to_document()
    validate_report_document(document)
    assert document["schema"] == "audit-report"
    assert document["schema_version"] == 1
    assert document["metadata"]["raw_provider_output_excluded"] is True
    assert "relative_path" not in document["evidence_references"][0]


def test_report_json_snapshot():
    document = sample_report().to_document()
    expected = (FIXTURE_DIR / "sample-report.json").read_text(encoding="utf-8")
    import json

    assert document == json.loads(expected)


def test_report_html_snapshot_and_escaping():
    html = render_html(sample_report())
    expected = (FIXTURE_DIR / "sample-report.html").read_text(encoding="utf-8")
    assert html == expected
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "alert(" not in html or "&quot;xss&quot;" in html
    assert "nmaprun" not in html
    assert "../" not in html
    assert "Краткое резюме" in html
    assert "Ссылки на доказательства" in html
    assert "Рекомендации" in html


def test_source_hash_is_stable_across_generation_time():
    first = sample_report()
    later = build_audit_report(
        sample_source(),
        report_id="33333333-3333-4000-8000-333333333333",
        generated_at=datetime(2026, 8, 25, 8, 0, tzinfo=timezone.utc),
        product="WireScope",
        version="0.1.0",
        job_id="22222222-2222-4000-8000-222222222222",
        actor="auditor",
    )
    assert first.source_hash == later.source_hash
    assert first.source_hash == source_hash_for(first)


def test_published_schema_rejects_missing_sections():
    document = sample_report().to_document()
    del document["findings"]
    with pytest.raises(SchemaValidationError, match="findings"):
        validate_report_document(document)


def test_recommendations_only_include_open_findings():
    report = sample_report(
        findings=[
            ReportFinding(
                id="finding-open",
                rule_id="WS-SMB-NULL-SESSION",
                rule_version="1",
                family="smb",
                title="SMB null session",
                severity="high",
                confidence="high",
                status="open",
                asset_id="asset-1",
                service_id="svc-1",
                description="Null session accepted.",
                rationale="smb_null_session.accepted is true.",
                recommendation="Disable unauthenticated SMB access.",
                observation_ids=["obs-2"],
                evidence_artifact_ids=[],
                data={},
            ),
            ReportFinding(
                id="finding-suppressed",
                rule_id="WS-HTTP-MISSING-HSTS",
                rule_version="1",
                family="http",
                title="Missing HSTS",
                severity="medium",
                confidence="high",
                status="suppressed",
                asset_id="asset-1",
                service_id="svc-1",
                description="HSTS was missing.",
                rationale="HTTPS response lacked Strict-Transport-Security.",
                recommendation="Enable HSTS.",
                observation_ids=["obs-3"],
                evidence_artifact_ids=[],
                data={},
            ),
        ]
    )
    assert [item.rule_id for item in report.recommendations] == [
        "WS-SMB-NULL-SESSION"
    ]
    assert report.executive_summary.open_finding_count == 1
    assert report.executive_summary.finding_count == 2
    assert report.executive_summary.highest_open_severity == "high"
