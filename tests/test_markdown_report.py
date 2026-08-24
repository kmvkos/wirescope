from reports.markdown import render_markdown


def test_markdown_renderer_uses_canonical_report_document():
    document = {
        "schema": "audit-report",
        "schema_version": 1,
        "report_id": "report-1",
        "generated_at": "2026-08-24T20:00:00Z",
        "audit": {
            "id": "audit-1",
            "status": "completed",
            "profile": "standard",
            "interface": "eth0",
        },
        "executive_summary": {
            "headline": "Two findings require attention",
            "summary": "The audit discovered one server and two findings.",
            "asset_count": 1,
            "service_count": 2,
            "finding_count": 2,
            "open_finding_count": 2,
            "highest_open_severity": "high",
        },
        "scope": {
            "confirmed": True,
            "profile": "standard",
            "interface": "eth0",
            "targets": ["192.0.2.0/24"],
            "address_count": 256,
        },
        "passive": {
            "available": True,
            "frame_count": 123,
            "visibility": "local-segment",
            "segment_status": "observed",
            "tagged_vlan_ids": [10],
            "arp_host_count": 3,
        },
        "assets": [
            {
                "id": "asset-1",
                "state": "responsive",
                "mac": "00:11:22:33:44:55",
                "vendor": "Example",
                "device_class_hint": "server-like",
                "os_name": "Linux",
                "addresses": ["192.0.2.10"],
                "names": ["srv-1"],
            }
        ],
        "services": [
            {
                "id": "service-1",
                "asset_id": "asset-1",
                "protocol": "tcp",
                "port": 22,
                "state": "open",
                "service_name": "ssh",
                "product": "OpenSSH",
                "version": "9.x",
            }
        ],
        "findings": [
            {
                "id": "finding-1",
                "rule_id": "WS-SSH-001",
                "title": "Weak SSH algorithm",
                "severity": "high",
                "confidence": "high",
                "status": "open",
                "asset_id": "asset-1",
                "service_id": "service-1",
                "description": "Legacy algorithm is offered.",
                "rationale": "The protocol observation contains the algorithm.",
                "recommendation": "Disable the legacy algorithm.",
            }
        ],
        "recommendations": [
            {
                "rule_id": "WS-SSH-001",
                "title": "Weak SSH algorithm",
                "severity": "high",
                "recommendation": "Disable the legacy algorithm.",
            }
        ],
        "evidence_references": [
            {
                "id": "artifact-1",
                "artifact_type": "ssh_audit_stdout",
                "content_type": "text/plain",
                "size": 120,
                "sha256": "abc123",
            }
        ],
    }

    rendered = render_markdown(document)

    assert rendered.startswith("# WireScope audit report")
    assert "192.0.2.0/24" in rendered
    assert "srv-1" in rendered
    assert "[HIGH] Weak SSH algorithm" in rendered
    assert "artifact-1" in rendered
    assert "Disable the legacy algorithm" in rendered
