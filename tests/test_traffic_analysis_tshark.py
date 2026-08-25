from dataclasses import replace
from pathlib import Path
import shutil

import pytest
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

from traffic_analysis.analyzer import TrafficAnalyzer


def test_real_tshark_decodes_retained_pcap(tmp_path: Path, durable_settings):
    tshark = shutil.which("tshark")
    if not tshark:
        pytest.skip("tshark is not installed")

    pcap = tmp_path / "traffic-analysis.pcap"
    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=51000, dport=443, flags="S"),
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:77")
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test")),
    ]
    wrpcap(str(pcap), packets)

    settings = replace(durable_settings, tshark_binary=tshark)
    document = TrafficAnalyzer(settings=settings).analyze(
        pcap,
        source={
            "capture_job_id": "fixture-capture",
            "interface": "eth0",
        },
    )

    assert document["schema"] == "traffic-analysis"
    assert document["summary"]["frame_count"] == 2
    assert document["summary"]["byte_count"] > 0
    assert document["summary"]["unique_ipv4"] == 3
    assert document["tcp"]["packets"] == 1
    assert document["dns"]["query_count"] == 1
    assert document["dns"]["top_names"][0]["name"] == "example.test"
    assert document["communications_graph"]["edges"]
