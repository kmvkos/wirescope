from traffic_analysis.analyzer import FIELDS, TrafficAnalyzer


def _row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in FIELDS) + "\n"


def test_traffic_analysis_persists_identity_resolution():
    rows = [
        _row(
            {
                "frame.number": "1",
                "frame.time_epoch": "1000.0",
                "frame.len": "60",
                "frame.protocols": "eth:arp",
                "eth.src": "00:11:22:33:44:55",
                "eth.dst": "00:11:22:33:44:01",
                "arp.opcode": "2",
                "arp.src.proto_ipv4": "10.0.0.10",
                "arp.src.hw_mac": "00:11:22:33:44:55",
                "arp.dst.proto_ipv4": "10.0.0.1",
                "arp.dst.hw_mac": "00:11:22:33:44:01",
            }
        )
    ]

    document = TrafficAnalyzer().analyze_tsv(
        rows,
        source={"capture_job_id": "capture-identity", "interface": "eth0"},
    )

    resolution = document["identity_resolution"]
    assert resolution["resolved_count"] == 1
    candidate = resolution["candidates"][0]
    assert candidate["candidate_id"] == "mac:00:11:22:33:44:55"
    assert candidate["addresses"] == ["10.0.0.10"]
    assert candidate["status"] == "resolved"
