from traffic_analysis.coherence import apply_product_coherence
from traffic_analysis.insights import enrich_document
from traffic_analysis.render_v5 import render_text


def test_protocol_presence_is_context_not_a_second_security_finding() -> None:
    document = {
        "summary": {"frame_count": 10, "byte_count": 1000},
        "tcp": {},
        "tcp_connections": {},
        "dns": {},
        "dns_latency": {},
        "broadcast_multicast": {},
        "conversations": [],
        "protocol_distribution": [],
        "observations": [
            {
                "severity": "warning",
                "category": "security",
                "title": "Обнаружен Telnet",
                "fact": "Telnet наблюдался в 4 кадрах.",
                "meaning": "legacy security wording",
                "check": "legacy remediation wording",
            },
            {
                "severity": "warning",
                "category": "arp",
                "title": "Один IP наблюдался с несколькими MAC",
                "fact": "10.0.0.1 -> two MACs",
                "meaning": "network diagnostic",
                "check": "verify ARP ownership",
            },
        ],
    }

    apply_product_coherence(document)
    telnet = document["observations"][0]
    arp = document["observations"][1]

    assert telnet["severity"] == "info"
    assert telnet["category"] == "protocol_visibility"
    assert telnet["assessment_owner"] == "audit_report"
    assert "не создаёт security finding" in telnet["meaning"]
    assert "Findings/Audit Report" in telnet["check"]

    # Real network-diagnostic warnings remain warnings.
    assert arp["severity"] == "warning"
    assert arp["category"] == "arp"

    enrich_document(document)
    assert document["diagnostic_summary"]["warning_count"] == 1
    assert document["diagnostic_summary"]["status"] == "attention"


def test_protocol_presence_alone_does_not_mark_capture_attention() -> None:
    document = {
        "summary": {"frame_count": 10, "byte_count": 1000},
        "tcp": {},
        "tcp_connections": {},
        "dns": {},
        "dns_latency": {},
        "broadcast_multicast": {},
        "conversations": [],
        "protocol_distribution": [],
        "observations": [
            {
                "severity": "warning",
                "category": "security",
                "title": "Обнаружен FTP",
                "fact": "FTP observed",
                "meaning": "legacy security wording",
                "check": "legacy remediation wording",
            }
        ],
    }

    apply_product_coherence(document)
    enrich_document(document)

    assert document["diagnostic_summary"]["warning_count"] == 0
    assert document["diagnostic_summary"]["status"] == "informational"


def test_final_text_report_does_not_repeat_dns_names_or_dhcp_servers() -> None:
    document = {
        "source": {"interface": "eth0", "capture_job_id": "capture-1"},
        "summary": {
            "frame_count": 20,
            "byte_count": 4096,
            "duration_seconds": 5,
            "unique_macs": 2,
            "unique_ipv4": 3,
            "unique_ipv6": 0,
        },
        "diagnostic_summary": {"status": "informational", "headline": "PCAP разобран."},
        "traffic_character": {
            "unicast_percent": 100.0,
            "broadcast_percent": 0.0,
            "multicast_percent": 0.0,
            "external_communications": [],
            "service_discovery": [],
        },
        "rates": {"frames_per_second": 4.0, "bytes_per_second": 819.2},
        "observations": [],
        "tcp": {},
        "tcp_connections": {},
        "dns": {
            "nxdomain": 0,
            "servfail": 0,
            "top_names": [{"name": "example.com", "count": 3}],
        },
        "dns_latency": {"samples": 0},
        "arp": {},
        "arp_diagnostics": {},
        "dhcp": {"server_hints": [{"endpoint": "10.0.0.1", "frames": 2}]},
        "icmp": {},
        "broadcast_multicast": {},
        "protocol_distribution": [],
        "top_talkers": [],
        "limitations": [],
        "protocol_intelligence": {
            "tls": {},
            "http": {},
            "quic": {},
            "smb": {},
            "dns": {
                "queries": 3,
                "responses": 3,
                "error_responses": 0,
                "clients": [{"endpoint": "10.0.0.20", "count": 3}],
                "servers": [{"endpoint": "10.0.0.53", "count": 3}],
                "names": [{"name": "example.com", "count": 3}],
                "rcodes": [{"rcode": "0", "count": 3}],
            },
            "dhcp": {
                "messages": [{"type": "ACK", "count": 1}],
                "transactions_seen": 1,
                "complete_dora": 0,
                "servers": [{"endpoint": "10.0.0.1", "count": 1}],
                "incomplete_sequences": [],
            },
        },
        "tcp_latency": {"status": "insufficient", "overall": {"samples": 0}},
    }

    rendered = render_text(document)

    # Detailed DNS/DHCP values are owned by Protocol Intelligence in the final
    # human-readable report, not repeated by the generic diagnostic section.
    assert rendered.count("example.com") == 1
    assert rendered.count("10.0.0.1") == 1
    assert "Наиболее частые наблюдаемые имена:" not in rendered
    assert "DHCP server hints:" not in rendered
    assert "ARP / DHCP / ICMP" not in rendered
    assert "ARP / ICMP" in rendered
