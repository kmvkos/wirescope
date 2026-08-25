from reports.markdown import render_markdown


def test_markdown_renderer_uses_canonical_report_document():
    document = {
        "schema": "audit-report",
        "schema_version": 1,
        "report_id": "report-1",
        "generated_at": "2026-08-24T20:00:00Z",
        "source_hash": "source-abc",
        "audit": {
            "id": "audit-1",
            "status": "completed",
            "profile": "standard",
            "interface": "eth0",
            "created_at": "2026-08-24T19:58:00Z",
            "started_at": "2026-08-24T19:59:00Z",
            "finished_at": "2026-08-24T20:00:00Z",
        },
        "executive_summary": {
            "headline": "Open high-severity findings were identified",
            "summary": "Аудит обнаружил один сервер и две проблемы.",
            "asset_count": 1,
            "service_count": 2,
            "finding_count": 2,
            "open_finding_count": 2,
            "highest_open_severity": "high",
            "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0},
        },
        "environment": {
            "hostname": "wirescope-node",
            "capture_interface": "eth0",
            "had_l3_address": True,
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
        "scope": {
            "confirmed": True,
            "profile": "standard",
            "interface": "eth0",
            "targets": ["192.0.2.0/24"],
            "address_count": 256,
            "address_families": [4],
            "timing_policy": "T3",
            "snapshot_hash": "scope-abc",
        },
        "passive": {
            "available": True,
            "capture_interface": "eth0",
            "capture_ipv4": ["192.0.2.10/24"],
            "capture_ipv6": [],
            "duration_seconds": 30,
            "frame_count": 123,
            "visibility": "local",
            "visibility_rationale": "Локальный трафик сегмента наблюдался.",
            "segment_status": "active",
            "segment_note": "Сегмент активен.",
            "tagged_vlan_ids": [10],
            "tagged_frame_count": 5,
            "untagged_traffic_observed": True,
            "port_type_hint": "trunk",
            "arp_host_count": 1,
            "arp_bindings": [
                {"ipv4": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:ff"}
            ],
            "neighbors": [
                {
                    "protocol": "LLDP",
                    "name": "switch-1",
                    "port_id": "Gi1/0/1",
                    "native_vlan": 10,
                    "voice_vlan": None,
                    "pvid": None,
                }
            ],
            "dhcp": {
                "observed": True,
                "server_count": 1,
                "servers": ["192.0.2.2"],
                "routers": ["192.0.2.1"],
                "subnet_masks": ["255.255.255.0"],
            },
            "stp": {
                "bpdus_observed": 2,
                "root_bridge_ids": ["root-1"],
                "bridge_ids": ["bridge-1"],
            },
            "naming": [
                {
                    "name": "mdns",
                    "status": "detected",
                    "hits": 2,
                    "names": ["host.local"],
                    "addresses": ["192.0.2.10"],
                }
            ],
            "detected_sensors": ["arp", "dhcpv4", "lldp", "mdns", "vlan"],
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
                "tunnel": None,
            }
        ],
        "findings": [
            {
                "id": "finding-1",
                "rule_id": "WS-SSH-001",
                "rule_version": "1",
                "family": "ssh",
                "title": "Слабый алгоритм SSH",
                "severity": "high",
                "confidence": "high",
                "status": "open",
                "asset_id": "asset-1",
                "service_id": "service-1",
                "description": "Служба предлагает устаревший алгоритм.",
                "rationale": "Наблюдение протокола содержит слабый алгоритм.",
                "recommendation": "Отключите устаревший алгоритм.",
                "evidence_artifact_ids": ["artifact-1"],
            }
        ],
        "recommendations": [
            {
                "rule_id": "WS-SSH-001",
                "title": "Слабый алгоритм SSH",
                "severity": "high",
                "recommendation": "Отключите устаревший алгоритм.",
                "affected_asset_ids": ["asset-1"],
            }
        ],
        "evidence_references": [
            {
                "id": "artifact-1",
                "artifact_type": "ssh_audit_stdout",
                "content_type": "text/plain",
                "size": 120,
                "sha256": "abc123",
                "created_at": "2026-08-24T20:00:00Z",
            }
        ],
        "metadata": {
            "version": "0.1.0",
            "actor": "auditor",
            "truncated": False,
            "raw_provider_output_excluded": True,
            "warnings": [],
        },
    }

    rendered = render_markdown(document)

    assert rendered.startswith("# Отчёт WireScope")
    assert "Есть проблемы высокой важности" in rendered
    assert "Open high-severity findings were identified" not in rendered
    assert "## Краткий итог" in rendered
    assert "## Покрытие и ограничения" in rendered
    assert "## Границы и параметры аудита" in rendered
    assert "## Окружение WireScope" in rendered
    assert "wirescope-node" in rendered
    assert "192.0.2.53" in rendered
    assert "T3" in rendered
    assert "## Пассивная картина сегмента" in rendered
    assert "switch-1" in rendered
    assert "192.0.2.2" in rendered
    assert "host.local" in rendered
    assert "aa:bb:cc:dd:ee:ff" in rendered
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
    assert "## Технические метаданные" in rendered
    assert "scope-abc" in rendered
    assert "# WireScope audit report" not in rendered
    assert "## Executive summary" not in rendered
