from traffic_analysis.render_v5 import render_markdown, render_text


def _document() -> dict:
    return {
        "source": {
            "interface": "eth0",
            "capture_job_id": "capture-12345678",
        },
        "summary": {
            "frame_count": 20,
            "byte_count": 2048,
            "duration_seconds": 5,
        },
        "diagnostic_summary": {
            # This is deliberately data, not a renderer label. Presentation
            # cleanup must not rewrite arbitrary operator/network values.
            "headline": "samples host is visible",
        },
        "traffic_character": {
            "unicast_percent": 70.0,
            "broadcast_percent": 20.0,
            "multicast_percent": 10.0,
        },
        "rates": {},
        "observations": [],
        "tcp": {
            "packets": 10,
            "retransmissions": 1,
            "retransmission_percent": 10.0,
            "lost_segments": 1,
            "duplicate_acks": 2,
            "out_of_order": 3,
            "zero_window": 0,
            "resets": 1,
        },
        "tcp_connections": {
            "streams_seen": 2,
            "attempted_streams": 1,
            "syn_ack_observed": 1,
        },
        "dns": {"nxdomain": 0, "servfail": 0},
        "dns_latency": {
            "samples": 4,
            "average_ms": 5.0,
            "p95_ms": 8.0,
            "max_ms": 10.0,
        },
        "arp": {"conflict_count": 0, "gratuitous_arp": 1},
        "arp_diagnostics": {
            "request_count": 3,
            "reply_count": 2,
            "unanswered_targets": [{"ip": "10.0.0.254", "requests": 2}],
        },
        "dhcp": {"server_hints": []},
        "icmp": {"diagnostic_error_count": 0},
        "broadcast_multicast": {
            "broadcast_frames": 4,
            "broadcast_percent": 20.0,
            "broadcast_bytes": 512,
            "multicast_frames": 2,
            "multicast_percent": 10.0,
            "multicast_bytes": 256,
            "top_multicast_sources": [{"endpoint": "10.0.0.2", "frames": 2}],
        },
        "protocol_distribution": [],
        "limitations": [],
        "protocol_intelligence": {
            "tls": {"frames": 0},
            "http": {"requests": 0, "responses": 0},
            "quic": {"frames": 0},
            "smb": {"frames": 0},
            "dns": {"queries": 0, "responses": 0},
            "dhcp": {"messages": []},
        },
        "tcp_latency": {
            "status": "measured",
            "overall": {
                "samples": 4,
                "average_ms": 5.0,
                "p50_ms": 4.0,
                "p95_ms": 8.0,
                "max_ms": 10.0,
            },
            "top_pairs": [],
        },
    }


def test_text_export_uses_operator_facing_russian_without_mutating_data():
    text = render_text(_document())

    assert "samples host is visible" in text
    assert "Повторные передачи:" in text
    assert "Признаки пропущенных или предыдущих сегментов:" in text
    assert "Дубли ACK / пакеты вне порядка:" in text
    assert "Нулевое TCP-окно / RST:" in text
    assert "Время ответа DNS: выборок 4; среднее 5.0 мс; p95 8.0 мс; максимум 10.0 мс." in text
    assert "ARP-запросы/ответы:" in text
    assert "Широковещательный трафик:" in text
    assert "Многоадресный трафик:" in text
    assert "Метаданные TLS в этом PCAP не выделены." in text

    for legacy in (
        "Retransmission:",
        "Previous/lost segment hints:",
        "Duplicate ACK / out-of-order:",
        "Zero Window / RST:",
        "DNS timing: samples",
        "ARP requests/replies:",
        "BROADCAST / MULTICAST",
        "TLS metadata в этом PCAP не выделены.",
    ):
        assert legacy not in text


def test_markdown_export_uses_same_presentation_vocabulary():
    markdown = render_markdown(_document())

    assert "samples host is visible" in markdown
    assert "- Повторные передачи:" in markdown
    assert "- Признаки пропущенных или предыдущих сегментов:" in markdown
    assert "- Дубли ACK / пакеты вне порядка:" in markdown
    assert "- Нулевое TCP-окно / RST:" in markdown
    assert "Время ответа DNS: выборок 4, p95 8.0 мс, максимум 10.0 мс." in markdown
    assert "## Широковещательный и многоадресный трафик" in markdown
    assert "Протокольный анализ использует только метаданные PCAP" in markdown

    for legacy in (
        "- Retransmission:",
        "- Previous/lost segment hints:",
        "- Duplicate ACK / out-of-order:",
        "- Zero Window / RST:",
        "DNS timing: samples",
        "## Broadcast / multicast",
        "Protocol Intelligence использует",
    ):
        assert legacy not in markdown
