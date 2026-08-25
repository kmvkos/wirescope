from reports.html_v2 import render_html
from tests.test_report_builder import sample_report


def test_modern_html_report_is_russian_readable_and_escapes_network_copy():
    html = render_html(sample_report())

    assert 'lang="ru"' in html
    assert "Результат аудита" in html
    assert "Есть проблемы высокой важности" in html
    assert "Open high-severity findings were identified" not in html
    assert "Покрытие и ограничения" in html
    assert "Обнаруженные проблемы" in html
    assert "Что обнаружено" in html
    assert "Почему это важно" in html
    assert "Что рекомендуется сделать" in html
    assert "План действий" in html
    assert "Устройства" in html
    assert "Обнаруженные службы" in html
    assert "Окружение WireScope" in html
    assert "192.0.2.53" in html
    assert "Политика таймингов" in html
    assert "T3" in html
    assert "Snapshot scope" in html
    assert "abc123" in html
    assert "Технические данные" in html
    assert "ВЫСОКАЯ" not in html  # HTML uses normal-case Russian badges.
    assert "Высокая" in html
    assert "Стандартный" in html
    assert "Сервер" in html

    # Finding titles are network/rule-derived content and must stay escaped.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "secret-tool-output" not in html


def test_modern_html_report_exposes_passive_network_context_without_raw_stdout():
    report = sample_report(
        passive_result={
            "result": {
                "interface": "eth0",
                "capture": {"frame_count": 42, "duration_seconds": 30},
                "assessment": {
                    "visibility": {
                        "value": "local",
                        "rationale": "Локальный трафик сегмента наблюдался.",
                    },
                    "layer2": {
                        "tagged_vlans_observed": [20],
                        "tagged_frame_count": 5,
                        "untagged_traffic_observed": True,
                        "port_type_hint": {"value": "trunk"},
                        "neighbors": [
                            {
                                "protocol": "LLDP",
                                "name": "switch-1",
                                "port_id": "Gi1/0/1",
                                "native_vlan": 10,
                            }
                        ],
                        "stp": {
                            "bpdus_observed": 2,
                            "root_bridge_ids": ["root-1"],
                            "bridge_ids": ["bridge-1"],
                        },
                    },
                },
                "sensors": {
                    "ethernet": {"status": "detected", "hits": 42},
                    "vlan": {"status": "detected", "hits": 5},
                    "arp": {
                        "status": "detected",
                        "summary": {
                            "unique_ipv4_hosts": 1,
                            "observed_ipv4_mac": [
                                {"ipv4": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:ff"}
                            ],
                        },
                    },
                    "dhcpv4": {
                        "status": "detected",
                        "summary": {
                            "server_count": 1,
                            "servers": [
                                {
                                    "server_id": "192.0.2.2",
                                    "routers": ["192.0.2.1"],
                                    "subnet_masks": ["255.255.255.0"],
                                }
                            ],
                        },
                    },
                    "mdns": {
                        "status": "detected",
                        "hits": 2,
                        "summary": {
                            "names": ["host.local"],
                            "addresses": ["192.0.2.10"],
                        },
                    },
                },
            }
        }
    )
    html = render_html(report)

    assert "Картина сетевого сегмента" in html
    assert "switch-1" in html
    assert "Gi1/0/1" in html
    assert "DHCPv4" in html
    assert "192.0.2.2" in html
    assert "Root bridge" in html
    assert "host.local" in html
    assert "aa:bb:cc:dd:ee:ff" in html
    assert "802.1Q VLAN" in html


def test_modern_html_report_has_print_and_mobile_layouts():
    html = render_html(sample_report())

    assert "@media print" in html
    assert "@media(max-width:560px)" in html
    assert 'class="toc"' in html
    assert 'id="executive-summary"' in html
    assert 'id="coverage"' in html
    assert 'id="environment"' in html
    assert 'id="technical"' in html
