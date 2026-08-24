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
            "headline": "Требуют внимания две проблемы",
            "summary": "Аудит обнаружил один сервер и две проблемы.",
            "asset_count": 1,
            "service_count": 2,
            "finding_count": 2,
            "open_finding_count": 2,
            "highest_open_severity": "high",
            "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0},
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
                "title": "Слабый алгоритм SSH",
                "severity": "high",
                "confidence": "high",
                "status": "open",
                "asset_id": "asset-1",
                "service_id": "service-1",
                "description": "Служба предлагает устаревший алгоритм.",
                "rationale": "Наблюдение протокола содержит слабый алгоритм.",
                "recommendation": "Отключите устаревший алгоритм.",
            }
        ],
        "recommendations": [
            {
                "rule_id": "WS-SSH-001",
                "title": "Слабый алгоритм SSH",
                "severity": "high",
                "recommendation": "Отключите устаревший алгоритм.",
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

    assert rendered.startswith("# Отчёт WireScope")
    assert "## Кратко" in rendered
    assert "## Обнаруженные проблемы" in rendered
    assert "## План действий" in rendered
    assert "**Статус:** завершён" in rendered
    assert "**Профиль:** стандартный" in rendered
    assert "192.0.2.0/24" in rendered
    assert "srv-1" in rendered
    assert "[ВЫСОКАЯ] Слабый алгоритм SSH" in rendered
    assert "**Что обнаружено:**" in rendered
    assert "**Почему это важно:**" in rendered
    assert "**Что рекомендуется сделать:**" in rendered
    assert "artifact-1" in rendered
    assert "Отключите устаревший алгоритм" in rendered
    assert "# WireScope audit report" not in rendered
    assert "## Executive summary" not in rendered
