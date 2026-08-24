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
    assert "Выводы" in html
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


def test_empty_capture_headline_is_honest():
    report = build_audit_report(
        sample_source(
            audit_summary={"schema": "passive-summary", "frame_count": 0},
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=[],
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    html = render_html(report)
    assert report.executive_summary.headline == "Capture completed with no frames"
    assert "Захват завершён: кадров нет" in html
    assert report.executive_summary.asset_count == 0


def test_no_ip_silent_tap_report_surfaces_environment_not_invented_vlans():
    report = build_audit_report(
        sample_source(
            audit_summary={"schema": "passive-summary", "frame_count": 0},
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=[],
            environment={
                "hostname": "wirescope-pi",
                "interfaces": [
                    {
                        "name": "eth0",
                        "state": "UP",
                        "mac": "02:00:00:00:00:aa",
                        "ipv4": [],
                        "ipv6": ["fe80::1/64"],
                    }
                ],
                "default_route": None,
                "dns": [],
            },
            passive_result={
                "schema": "passive-result",
                "schema_version": 1,
                "result": {
                    "interface": "eth0",
                    "interface_ipv4": [],
                    "interface_ipv6": ["fe80::1/64"],
                    "capture": {
                        "frame_count": 0,
                        "duration_seconds": 30,
                    },
                    "sensors": {},
                    "assessment": {
                        "visibility": {
                            "value": "silent",
                            "rationale": "Capture completed and contained no frames",
                        },
                        "layer2": {
                            "tagged_vlans_observed": [],
                            "tagged_frame_count": 0,
                            "untagged_traffic_observed": False,
                            "neighbors": [],
                        },
                    },
                },
            },
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    html = render_html(report)
    validate_report_document(report.to_document())
    assert report.passive.had_l3_address is False
    assert report.passive.tagged_vlan_ids == []
    assert report.passive.segment_status == "quiet"
    assert report.executive_summary.headline == "Capture completed with no frames"
    assert "eth0" in html
    assert "L3-адрес" in html
    assert "Сегмент выглядел тихим" in html
    assert "Пассивная оценка сегмента" in html
    assert "VLAN в кадре виден только при 802.1Q" in html
    assert "VLAN 1" not in html


def test_no_ip_tagged_and_neighbor_observations_appear_in_html():
    report = build_audit_report(
        sample_source(
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=["vlan", "lldp", "cdp", "arp"],
            environment={
                "hostname": "wirescope-pi",
                "interfaces": [
                    {
                        "name": "eth0",
                        "state": "UP",
                        "mac": "02:00:00:00:00:aa",
                        "ipv4": [],
                        "ipv6": [],
                    }
                ],
                "default_route": None,
                "dns": [],
            },
            passive_result={
                "result": {
                    "interface": "eth0",
                    "interface_ipv4": [],
                    "interface_ipv6": [],
                    "capture": {"frame_count": 40, "duration_seconds": 30},
                    "sensors": {
                        "vlan": {
                            "status": "detected",
                            "hits": 8,
                            "summary": {
                                "tagged_frames": 8,
                                "vlan_frame_counts": [
                                    {"vlan_id": 10, "frames": 5},
                                    {"vlan_id": 20, "frames": 3},
                                ],
                            },
                        },
                        "lldp": {
                            "status": "detected",
                            "hits": 1,
                            "observations": [
                                {
                                    "kind": "neighbor_advertisement",
                                    "data": {
                                        "system_name": "core-sw",
                                        "port_id": "Gi1/0/24",
                                        "pvid": 10,
                                        "voice_vlan": 40,
                                    },
                                }
                            ],
                        },
                        "cdp": {
                            "status": "detected",
                            "hits": 1,
                            "observations": [
                                {
                                    "kind": "neighbor_advertisement",
                                    "data": {
                                        "device_id": "access-sw",
                                        "port_id": "Gi1/0/1",
                                        "native_vlan": 20,
                                        "voice_vlan": 30,
                                    },
                                }
                            ],
                        },
                        "arp": {
                            "status": "detected",
                            "hits": 2,
                            "summary": {
                                "unique_ipv4_hosts": 2,
                                "observed_ipv4_mac": [
                                    {
                                        "ipv4": "192.0.2.1",
                                        "mac": "02:00:00:00:00:01",
                                    }
                                ],
                            },
                        },
                        "mdns": {
                            "status": "detected",
                            "hits": 1,
                            "summary": {
                                "names": ["printer.local"],
                                "addresses": [],
                            },
                        },
                        "llmnr": {"status": "absent", "hits": 0, "summary": {}},
                        "nbns": {"status": "absent", "hits": 0, "summary": {}},
                    },
                    "assessment": {
                        "visibility": {
                            "value": "active",
                            "rationale": "traffic",
                        },
                        "layer2": {
                            "tagged_vlans_observed": [10, 20],
                            "tagged_frame_count": 8,
                            "untagged_traffic_observed": True,
                            "port_type_hint": {"value": "trunk-like"},
                            "neighbors": [
                                {
                                    "protocol": "LLDP",
                                    "system_name": "core-sw",
                                    "port_id": "Gi1/0/24",
                                    "pvid": 10,
                                    "voice_vlan": 40,
                                },
                                {
                                    "protocol": "CDP",
                                    "device_id": "access-sw",
                                    "port_id": "Gi1/0/1",
                                    "native_vlan": 20,
                                    "voice_vlan": 30,
                                },
                            ],
                        },
                    },
                }
            },
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    html = render_html(report)
    document = report.to_document()
    validate_report_document(document)
    assert report.executive_summary.headline == "Saw tagged VLANs 10, 20"
    assert report.passive.had_l3_address is False
    assert report.passive.tagged_vlan_ids == [10, 20]
    assert {item.name for item in report.passive.neighbors} == {
        "core-sw",
        "access-sw",
    }
    assert "В кадрах видны тегированные VLAN 10, 20" in html
    assert "core-sw" in html
    assert "Gi1/0/24" in html
    assert "native VLAN 20" in html
    assert "voice VLAN 30" in html
    assert "printer.local" in html
    assert "192.0.2.1" in html
    assert report.passive.vlan_tag_note.startswith("VLAN в кадре виден только")


def test_untagged_access_port_does_not_claim_a_vlan_id():
    report = build_audit_report(
        sample_source(
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=["ethernet", "arp"],
            environment={
                "hostname": "wirescope-pi",
                "interfaces": [
                    {
                        "name": "eth0",
                        "state": "UP",
                        "mac": "02:00:00:00:00:aa",
                        "ipv4": [],
                        "ipv6": [],
                    }
                ],
                "default_route": None,
                "dns": [],
            },
            passive_result={
                "result": {
                    "interface": "eth0",
                    "interface_ipv4": [],
                    "capture": {"frame_count": 25, "duration_seconds": 30},
                    "sensors": {
                        "ethernet": {
                            "status": "detected",
                            "hits": 25,
                            "summary": {},
                        },
                        "vlan": {
                            "status": "absent",
                            "hits": 0,
                            "summary": {
                                "tagged_frames": 0,
                                "vlan_frame_counts": [],
                            },
                        },
                        "arp": {
                            "status": "detected",
                            "hits": 4,
                            "summary": {
                                "unique_ipv4_hosts": 3,
                                "observed_ipv4_mac": [],
                            },
                        },
                    },
                    "assessment": {
                        "visibility": {"value": "active"},
                        "layer2": {
                            "tagged_vlans_observed": [],
                            "tagged_frame_count": 0,
                            "untagged_traffic_observed": True,
                            "port_type_hint": {
                                "value": "access-or-native-like",
                            },
                            "neighbors": [],
                        },
                    },
                }
            },
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    html = render_html(report)
    assert report.passive.tagged_vlan_ids == []
    assert report.executive_summary.headline == (
        "Untagged traffic was observed; VLAN ID is unknown"
    )
    assert "ID VLAN неизвестен" in html
    assert "access-or-native-like" in html
    assert "VLAN 1" not in html


def test_executive_conclusion_is_russian_narrative():
    report = sample_report()
    summary = report.executive_summary
    assert summary.summary_schema == "executive-conclusion"
    assert summary.summary_version == 1
    assert "слабые алгоритмы SSH" in summary.summary
    assert "высокие — 1" in summary.summary
    assert "Nmap не запускался" in summary.summary
    html = render_html(report)
    assert "Выводы" in html
    assert summary.summary.split("\n\n")[0] in html


def test_executive_conclusion_quiet_and_empty_inventory_is_not_all_clear():
    report = build_audit_report(
        sample_source(
            audit_summary={"schema": "passive-summary", "frame_count": 0},
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=[],
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    text = report.executive_summary.summary
    assert "Сегмент тихий" in text
    assert "Открытых слабых мест нет" in text
    assert "Nmap не запускался" in text
    assert "всё чисто" not in text


def test_executive_conclusion_hosts_without_findings_are_not_all_clear():
    report = build_audit_report(
        sample_source(
            findings=[],
            detected_sensors=["arp"],
            audit_summary={"schema": "passive-summary", "frame_count": 25},
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    text = report.executive_summary.summary
    assert "не «всё чисто»" in text
    assert "активн" in text.lower()


def test_executive_conclusion_includes_vlan_caveat_without_l3():
    report = build_audit_report(
        sample_source(
            confirmed_scope=None,
            assets=[],
            services=[],
            findings=[],
            detected_sensors=["vlan"],
            environment={
                "hostname": "wirescope-pi",
                "interfaces": [
                    {
                        "name": "eth0",
                        "state": "UP",
                        "mac": "02:00:00:00:00:aa",
                        "ipv4": [],
                        "ipv6": [],
                    }
                ],
                "default_route": None,
                "dns": [],
            },
            passive_result={
                "result": {
                    "interface": "eth0",
                    "interface_ipv4": [],
                    "interface_ipv6": [],
                    "capture": {"frame_count": 40, "duration_seconds": 30},
                    "sensors": {
                        "vlan": {
                            "status": "detected",
                            "hits": 8,
                            "summary": {
                                "tagged_frames": 8,
                                "vlan_frame_counts": [
                                    {"vlan_id": 10, "frames": 5},
                                    {"vlan_id": 20, "frames": 3},
                                ],
                            },
                        },
                        "dhcpv4": {"status": "absent", "hits": 0, "summary": {}},
                    },
                    "assessment": {
                        "layer2": {
                            "tagged_vlans_observed": [10, 20],
                            "tagged_frame_count": 8,
                            "untagged_traffic_observed": True,
                        }
                    },
                }
            },
        ),
        report_id=REPORT_ID,
        generated_at=FROZEN,
        product="WireScope",
        version="0.1.0",
    )
    text = report.executive_summary.summary
    assert "VLAN 10, 20" in text
    assert "Нет L3-адреса" in text or "нет L3-адреса" in text
    assert "access-порт" in text
    html = render_html(report)
    assert "Выводы" in html
    assert "VLAN 10, 20" in html

