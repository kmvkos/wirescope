from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, TCP, UDP, wrpcap

from config.settings import get_settings
from traffic_analysis.advanced import FIELDS, AdvancedTrafficAnalyzer, merge_advanced
from traffic_analysis.advanced_compat import PortableAdvancedTrafficAnalyzer
from traffic_analysis.analyzer import TrafficAnalyzer
from traffic_analysis.render_v2 import render_markdown, render_text


def _row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in FIELDS) + "\n"


def test_advanced_streaming_diagnostics_attribute_tcp_dns_arp_and_icmp():
    rows = [
        _row({
            "frame.number": "1",
            "frame.time_epoch": "1000.0",
            "frame.len": "60",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.stream": "1",
            "tcp.srcport": "50000",
            "tcp.dstport": "443",
            "tcp.flags.syn": "1",
            "tcp.flags.ack": "0",
        }),
        _row({
            "frame.number": "2",
            "frame.time_epoch": "1001.0",
            "frame.len": "60",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.stream": "1",
            "tcp.srcport": "50000",
            "tcp.dstport": "443",
            "tcp.flags.syn": "1",
            "tcp.flags.ack": "0",
            "tcp.analysis.retransmission": "1",
            "tcp.analysis.syn_retransmission": "1",
        }),
        _row({
            "frame.number": "3",
            "frame.time_epoch": "1001.2",
            "frame.len": "80",
            "ip.src": "10.0.0.53",
            "ip.dst": "10.0.0.2",
            "udp.srcport": "53",
            "udp.dstport": "53000",
            "dns.qry.name": "slow.example",
            "dns.flags.response": "1",
            "dns.flags.rcode": "3",
            "dns.time": "0.750",
        }),
        _row({
            "frame.number": "4",
            "frame.time_epoch": "1001.3",
            "frame.len": "42",
            "arp.opcode": "1",
            "arp.src.proto_ipv4": "10.0.0.2",
            "arp.src.hw_mac": "00:00:00:00:00:02",
            "arp.dst.proto_ipv4": "10.0.0.77",
        }),
        _row({
            "frame.number": "5",
            "frame.time_epoch": "1001.4",
            "frame.len": "42",
            "arp.opcode": "1",
            "arp.src.proto_ipv4": "10.0.0.2",
            "arp.src.hw_mac": "00:00:00:00:00:02",
            "arp.dst.proto_ipv4": "10.0.0.77",
        }),
        _row({
            "frame.number": "6",
            "frame.time_epoch": "1001.5",
            "frame.len": "42",
            "arp.opcode": "1",
            "arp.src.proto_ipv4": "10.0.0.2",
            "arp.src.hw_mac": "00:00:00:00:00:02",
            "arp.dst.proto_ipv4": "10.0.0.77",
        }),
        _row({
            "frame.number": "7",
            "frame.time_epoch": "1001.6",
            "frame.len": "100",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "icmp.type": "3",
            "icmp.code": "1",
        }),
        _row({
            "frame.number": "8",
            "frame.time_epoch": "1001.7",
            "frame.len": "100",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "icmp.type": "3",
            "icmp.code": "1",
        }),
        _row({
            "frame.number": "9",
            "frame.time_epoch": "1002.0",
            "frame.len": "100",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "icmp.type": "3",
            "icmp.code": "1",
        }),
    ]

    result = AdvancedTrafficAnalyzer().analyze_tsv(rows)
    assert result["rates"]["frames_per_second"] == 4.5
    assert result["tcp_connections"]["attempted_streams"] == 1
    assert result["tcp_connections"]["no_syn_ack_observed"] == 1
    assert result["tcp_connections"]["syn_retransmission_streams"] == 1
    assert result["tcp_connections"]["top_problem_pairs"][0]["endpoint_a"] == "10.0.0.10"
    assert result["dns_latency"]["samples"] == 1
    assert result["dns_latency"]["max_ms"] == 750.0
    assert result["dns_latency"]["top_error_names"][0]["name"] == "slow.example"
    assert result["arp_diagnostics"]["unanswered_targets"][0] == {
        "ip": "10.0.0.77",
        "requests": 3,
    }
    assert result["icmp"]["diagnostic_error_count"] == 3
    titles = {item["title"] for item in result["observations"]}
    assert "Повторные ARP-запросы без наблюдаемого ответа" in titles
    assert "Наблюдались диагностические ICMP-сообщения" in titles


def test_extended_renderer_surfaces_health_and_problem_pairs():
    base = TrafficAnalyzer().analyze_tsv(
        [],
        source={"capture_job_id": "capture", "interface": "eth0"},
    )
    advanced = {
        "rates": {"frames_per_second": 125.5, "megabits_per_second": 8.75},
        "tcp_connections": {
            "streams_seen": 12,
            "attempted_streams": 10,
            "syn_ack_observed": 7,
            "no_syn_ack_observed": 3,
            "syn_retransmission_streams": 2,
            "reset_streams": 1,
            "top_problem_pairs": [
                {
                    "endpoint_a": "10.0.0.2",
                    "endpoint_b": "10.0.0.10",
                    "retransmissions": 4,
                    "duplicate_acks": 2,
                    "out_of_order": 1,
                    "zero_window": 0,
                    "resets": 1,
                    "syn_retransmissions": 2,
                }
            ],
        },
        "dns_latency": {
            "samples": 5,
            "average_ms": 120.0,
            "p50_ms": 80.0,
            "p95_ms": 550.0,
            "max_ms": 800.0,
            "slow_names": [],
        },
        "arp_diagnostics": {"request_count": 10, "reply_count": 8, "unanswered_targets": []},
        "icmp": {"diagnostic_error_count": 2, "types": []},
        "observations": [
            {
                "severity": "warning",
                "category": "dns",
                "title": "Повышенное время ответа DNS",
                "fact": "p95 550 мс",
                "meaning": "DNS отвечает медленно",
                "check": "Проверить резолвер",
            }
        ],
    }
    merge_advanced(base, advanced)
    text = render_text(base)
    markdown = render_markdown(base)
    assert "СОСТОЯНИЕ ЗАХВАТА" in text
    assert "ТРЕБУЕТ ВНИМАНИЯ" in text
    assert "РАСШИРЕННАЯ ДИАГНОСТИКА" in text
    assert "10.0.0.2 ↔ 10.0.0.10" in text
    assert "## Состояние захвата" in markdown
    assert "## Расширенная диагностика" in markdown


def test_advanced_analyzer_runs_against_real_tshark(tmp_path: Path):
    pcap = tmp_path / "advanced.pcap"
    packets = []

    syn = Ether()/IP(src="10.1.0.2", dst="10.1.0.10")/TCP(sport=51000, dport=443, flags="S", seq=100)
    syn.time = 1000.0
    packets.append(syn)
    syn_retry = Ether()/IP(src="10.1.0.2", dst="10.1.0.10")/TCP(sport=51000, dport=443, flags="S", seq=100)
    syn_retry.time = 1001.0
    packets.append(syn_retry)

    query = Ether()/IP(src="10.1.0.2", dst="10.1.0.53")/UDP(sport=53000, dport=53)/DNS(id=7, rd=1, qd=DNSQR(qname="example.test"))
    query.time = 1002.0
    packets.append(query)
    reply = Ether()/IP(src="10.1.0.53", dst="10.1.0.2")/UDP(sport=53, dport=53000)/DNS(
        id=7,
        qr=1,
        aa=1,
        qd=DNSQR(qname="example.test"),
        an=DNSRR(rrname="example.test", rdata="192.0.2.10"),
    )
    reply.time = 1002.2
    packets.append(reply)

    arp = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/ARP(
        op=1,
        psrc="10.1.0.2",
        pdst="10.1.0.77",
        hwsrc="00:11:22:33:44:55",
    )
    arp.time = 1003.0
    packets.append(arp)

    icmp = Ether()/IP(src="10.1.0.1", dst="10.1.0.2")/ICMP(type=3, code=1)
    icmp.time = 1004.0
    packets.append(icmp)
    wrpcap(str(pcap), packets)

    settings = get_settings()
    result = PortableAdvancedTrafficAnalyzer(settings=settings).analyze(pcap)
    assert result["rates"]["frames_per_second"] > 0
    assert result["tcp_connections"]["streams_seen"] >= 1
    assert result["tcp_connections"]["syn_retransmission_streams"] >= 1
    assert result["dns_latency"]["samples"] >= 1
    assert result["dns_latency"]["max_ms"] >= 190
    assert result["arp_diagnostics"]["request_count"] >= 1
    assert result["icmp"]["types"]
