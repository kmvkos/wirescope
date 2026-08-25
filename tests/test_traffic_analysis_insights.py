from traffic_analysis.insights import enrich_document
from traffic_analysis.render_v3 import render_markdown, render_text


def _sample_document():
    return {
        "source": {"interface": "ens37", "capture_job_id": "463ce332-test"},
        "summary": {
            "frame_count": 135,
            "byte_count": 82432,
            "duration_seconds": 59,
            "unique_macs": 28,
            "unique_ipv4": 10,
            "unique_ipv6": 22,
        },
        "rates": {
            "frames_per_second": 2.26,
            "bytes_per_second": 1397.15,
            "megabits_per_second": 0.011,
        },
        "tcp": {
            "packets": 48,
            "retransmissions": 0,
            "retransmission_percent": 0.0,
            "duplicate_acks": 0,
            "out_of_order": 0,
            "lost_segments": 17,
            "zero_window": 0,
            "resets": 0,
        },
        "tcp_connections": {
            "streams_seen": 2,
            "attempted_streams": 0,
            "syn_ack_observed": 0,
            "no_syn_ack_observed": 0,
            "syn_retransmission_streams": 0,
            "reset_streams": 0,
            "top_problem_pairs": [],
        },
        "dns": {
            "top_names": [{"name": "_yandexio._tcp.local", "count": 2}],
            "nxdomain": 0,
            "servfail": 0,
        },
        "dns_latency": {
            "samples": 2,
            "average_ms": 78.5,
            "p50_ms": 78.5,
            "p95_ms": 100.3,
            "max_ms": 102.8,
        },
        "arp": {"conflict_count": 0, "gratuitous_arp": 0},
        "arp_diagnostics": {"request_count": 2, "reply_count": 2, "unanswered_targets": []},
        "dhcp": {"server_hints": []},
        "icmp": {"diagnostic_error_count": 0, "types": []},
        "broadcast_multicast": {
            "broadcast_frames": 4,
            "broadcast_bytes": 506,
            "broadcast_percent": 2.96,
            "multicast_frames": 69,
            "multicast_bytes": 8192,
            "multicast_percent": 51.11,
            "top_broadcast_sources": [{"endpoint": "10.11.11.11", "frames": 2}],
            "top_multicast_sources": [
                {"endpoint": "fe80::d69c:53ff:fe13:b4b1", "frames": 30},
                {"endpoint": "10.11.11.37", "frames": 25},
            ],
        },
        "protocol_distribution": [
            {"name": "tls", "frames": 46, "percent": 34.07},
            {"name": "icmpv6", "frames": 42, "percent": 31.11},
            {"name": "udp", "frames": 27, "percent": 20.0},
            {"name": "ssdp", "frames": 8, "percent": 5.93},
            {"name": "mdns", "frames": 4, "percent": 2.96},
        ],
        "conversations": [
            {
                "endpoint_a": "10.11.11.82",
                "endpoint_b": "92.63.177.83",
                "bytes": 72500,
                "packets": 48,
                "protocols": [{"name": "tls", "frames": 46}, {"name": "tcp", "frames": 2}],
                "ports": [{"port": "tcp/443", "frames": 48}],
            },
            {
                "endpoint_a": "10.11.11.37",
                "endpoint_b": "224.0.0.224",
                "bytes": 1500,
                "packets": 23,
                "protocols": [{"name": "udp", "frames": 23}],
                "ports": [],
            },
        ],
        "top_talkers": [
            {"endpoint": "10.11.11.82", "bytes": 73300, "packets": 52},
            {"endpoint": "92.63.177.83", "bytes": 72500, "packets": 48},
        ],
        "observations": [],
        "limitations": ["Выводы относятся только к трафику, попавшему в этот PCAP."],
    }


def test_insights_turn_sample_statistics_into_operator_diagnosis():
    document = enrich_document(_sample_document())

    titles = [item["title"] for item in document["observations"]]
    assert "В захвате есть признаки пропущенных TCP-сегментов" in titles
    assert "Начало наблюдаемых TCP-соединений не попало в захват" in titles
    assert "Большая часть видимого трафика — multicast" in titles
    assert "Захват в основном занят одной парой узлов" in titles

    assert document["diagnostic_summary"]["status"] == "attention"
    assert document["traffic_character"]["dominant_flow"]["endpoint_a"] == "10.11.11.82"
    assert document["traffic_character"]["dominant_flow"]["percent_of_capture_bytes"] > 80
    assert document["traffic_character"]["external_communications"][0]["endpoint_b"] == "92.63.177.83"
    assert document["dns_latency"]["interpretation"] == "local_name_resolution"

    text = render_text(document)
    assert "WIRESCOPE — ДИАГНОСТИКА PCAP" in text
    assert "КРАТКИЙ ДИАГНОЗ" in text
    assert "ТРЕБУЕТ ПРОВЕРКИ" in text
    assert "previous/lost segment hints" in text.lower()
    assert "10.11.11.82 ↔ 92.63.177.83" in text
    assert "не трактуется как latency обычного DNS-резолвера" in text

    markdown = render_markdown(document)
    assert "# WireScope — диагностика PCAP" in markdown
    assert "## Краткий диагноз" in markdown
    assert "Previous/lost segment hints" in markdown
