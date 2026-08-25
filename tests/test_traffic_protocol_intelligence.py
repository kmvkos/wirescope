from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap

from config.settings import get_settings
from traffic_analysis.protocol_intelligence import (
    ProtocolIntelligenceAnalyzer,
    merge_protocol_intelligence,
)
from traffic_analysis.render_v4 import render_markdown, render_text


def _row(fields, values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in fields) + "\n"


def test_protocol_intelligence_builds_tls_http_quic_smb_dns_and_dhcp():
    fields = [
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.extensions_alpn_str",
        "http.host",
        "http.request.method",
        "http.response.code",
        "quic.version",
        "smb2.cmd",
        "smb2.nt_status",
        "dns.qry.name",
        "dns.flags.response",
        "dns.flags.rcode",
        "dns.a",
        "dhcp.id",
        "dhcp.option.dhcp",
        "dhcp.option.hostname",
        "dhcp.option.dhcp_server_id",
    ]
    rows = [
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:tls",
            "ip.src": "10.0.0.2",
            "ip.dst": "198.51.100.20",
            "tcp.srcport": "51000",
            "tcp.dstport": "443",
            "tls.handshake.extensions_server_name": "api.example.test",
            "tls.handshake.extensions.supported_version": "0x0304",
            "tls.handshake.extensions_alpn_str": "h2",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:http",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.srcport": "52000",
            "tcp.dstport": "80",
            "http.host": "app.internal",
            "http.request.method": "GET",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:http",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "80",
            "tcp.dstport": "52000",
            "http.response.code": "500",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:http",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "80",
            "tcp.dstport": "52000",
            "http.response.code": "502",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:http",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "80",
            "tcp.dstport": "52000",
            "http.response.code": "503",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:udp:quic",
            "ip.src": "10.0.0.2",
            "ip.dst": "203.0.113.10",
            "udp.srcport": "53000",
            "udp.dstport": "443",
            "quic.version": "0x00000001",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:tcp:nbss:smb2",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.20",
            "tcp.srcport": "54000",
            "tcp.dstport": "445",
            "smb2.cmd": "8",
            "smb2.nt_status": "0x00000000",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:udp:dns",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.53",
            "udp.srcport": "55000",
            "udp.dstport": "53",
            "dns.qry.name": "example.test",
            "dns.flags.response": "0",
        }),
        _row(fields, {
            "frame.protocols": "eth:ip:udp:dns",
            "ip.src": "10.0.0.53",
            "ip.dst": "10.0.0.2",
            "udp.srcport": "53",
            "udp.dstport": "55000",
            "dns.qry.name": "example.test",
            "dns.flags.response": "1",
            "dns.flags.rcode": "0",
            "dns.a": "192.0.2.55",
        }),
        # mDNS deliberately carries dns.* fields but must not pollute ordinary DNS.
        _row(fields, {
            "frame.protocols": "eth:ip:udp:mdns:dns",
            "ip.src": "10.0.0.5",
            "ip.dst": "224.0.0.251",
            "udp.srcport": "5353",
            "udp.dstport": "5353",
            "dns.qry.name": "printer.local",
            "dns.flags.response": "0",
        }),
    ]

    dora = [("1", "DISCOVER", "0.0.0.0", "255.255.255.255", "68", "67"),
            ("2", "OFFER", "10.0.0.1", "255.255.255.255", "67", "68"),
            ("3", "REQUEST", "0.0.0.0", "255.255.255.255", "68", "67"),
            ("5", "ACK", "10.0.0.1", "255.255.255.255", "67", "68")]
    for code, _label, src, dst, sport, dport in dora:
        rows.append(_row(fields, {
            "frame.protocols": "eth:ip:udp:dhcp",
            "ip.src": src,
            "ip.dst": dst,
            "udp.srcport": sport,
            "udp.dstport": dport,
            "dhcp.id": "0x12345678",
            "dhcp.option.dhcp": code,
            "dhcp.option.hostname": "client-01" if code in {"1", "3"} else "",
            "dhcp.option.dhcp_server_id": "10.0.0.1" if code in {"2", "5"} else "",
        }))

    result = ProtocolIntelligenceAnalyzer().analyze_tsv(rows, fields=fields)

    assert result["tls"]["sni"][0]["name"] == "api.example.test"
    assert result["tls"]["versions"][0]["version"] == "TLS 1.3"
    assert result["tls"]["alpn"][0]["protocol"] == "h2"
    assert result["http"]["requests"] == 1
    assert result["http"]["server_errors_5xx"] == 3
    assert result["quic"]["frames"] == 1
    assert result["smb"]["commands"][0]["command"] == "READ"
    assert result["dns"]["queries"] == 1
    assert result["dns"]["responses"] == 1
    assert result["dns"]["names"] == [{"name": "example.test", "count": 2}]
    assert result["dhcp"]["complete_dora"] == 1
    assert result["dhcp"]["servers"][0]["endpoint"] == "10.0.0.1"
    titles = {item["title"] for item in result["observations"]}
    assert "В HTTP наблюдались серверные ошибки 5xx" in titles

    document = {
        "summary": {"frame_count": 20, "byte_count": 2000, "duration_seconds": 5},
        "source": {"interface": "eth0", "capture_job_id": "capture-1"},
        "diagnostic_summary": {"status": "attention", "headline": "Есть сигналы"},
        "traffic_character": {},
        "rates": {},
        "observations": result["observations"],
        "tcp": {},
        "tcp_connections": {},
        "dns": {},
        "dns_latency": {},
        "arp": {},
        "arp_diagnostics": {},
        "dhcp": {},
        "icmp": {},
        "broadcast_multicast": {},
        "protocol_distribution": [],
        "top_talkers": [],
        "conversations": [],
        "limitations": [],
    }
    merge_protocol_intelligence(document, result)
    text = render_text(document)
    markdown = render_markdown(document)
    assert "ПРОТОКОЛЬНЫЙ РАЗБОР" in text
    assert "api.example.test" in text
    assert "HTTP Host" in text
    assert "DISCOVER" in text
    assert "## Протокольный разбор" in markdown


def test_protocol_intelligence_runs_against_real_tshark(tmp_path: Path):
    pcap = tmp_path / "protocol-intelligence.pcap"
    packet = (
        Ether()
        / IP(src="10.1.0.2", dst="10.1.0.53")
        / UDP(sport=53000, dport=53)
        / DNS(id=7, rd=1, qd=DNSQR(qname="example.test"))
    )
    packet.time = 1000.0
    wrpcap(str(pcap), [packet])

    result = ProtocolIntelligenceAnalyzer(settings=get_settings()).analyze(pcap)
    assert "field_coverage" in result
    assert result["dns"]["queries"] == 1
    assert result["dns"]["names"][0]["name"] == "example.test"
