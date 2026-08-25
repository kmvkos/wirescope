from traffic_analysis.analyzer import FIELDS, TrafficAnalyzer
from traffic_analysis.render import render_markdown, render_text
from jobs.models import RetentionClass
from jobs.worker import build_registry
from tests.helpers import http_request as request


def _row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in FIELDS) + "\n"


def test_streaming_traffic_analysis_builds_diagnostics_and_graph():
    rows = [
        _row({
            "frame.number": "1",
            "frame.time_epoch": "1000.0",
            "frame.len": "100",
            "frame.protocols": "eth:ip:tcp:http",
            "eth.src": "00:00:00:00:00:02",
            "eth.dst": "00:00:00:00:00:10",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.srcport": "51500",
            "tcp.dstport": "80",
            "tcp.analysis.retransmission": "1",
        }),
        _row({
            "frame.number": "2",
            "frame.time_epoch": "1000.1",
            "frame.len": "120",
            "frame.protocols": "eth:ip:tcp:http",
            "eth.src": "00:00:00:00:00:10",
            "eth.dst": "00:00:00:00:00:02",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "80",
            "tcp.dstport": "51500",
            "tcp.flags.reset": "1",
        }),
        _row({
            "frame.number": "3",
            "frame.time_epoch": "1001.0",
            "frame.len": "90",
            "frame.protocols": "eth:ip:udp:dns",
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.53",
            "udp.srcport": "53000",
            "udp.dstport": "53",
            "dns.qry.name": "missing.example",
        }),
        _row({
            "frame.number": "4",
            "frame.time_epoch": "1001.1",
            "frame.len": "110",
            "frame.protocols": "eth:ip:udp:dns",
            "ip.src": "10.0.0.53",
            "ip.dst": "10.0.0.2",
            "udp.srcport": "53",
            "udp.dstport": "53000",
            "dns.qry.name": "missing.example",
            "dns.flags.rcode": "3",
        }),
        _row({
            "frame.number": "5",
            "frame.time_epoch": "1002.0",
            "frame.len": "60",
            "frame.protocols": "eth:arp",
            "eth.src": "00:00:00:00:00:01",
            "eth.dst": "ff:ff:ff:ff:ff:ff",
            "arp.src.proto_ipv4": "10.0.0.1",
            "arp.src.hw_mac": "00:00:00:00:00:01",
            "arp.dst.proto_ipv4": "10.0.0.1",
            "arp.dst.hw_mac": "00:00:00:00:00:00",
        }),
        _row({
            "frame.number": "6",
            "frame.time_epoch": "1002.1",
            "frame.len": "60",
            "frame.protocols": "eth:arp",
            "eth.src": "00:00:00:00:00:99",
            "eth.dst": "ff:ff:ff:ff:ff:ff",
            "arp.src.proto_ipv4": "10.0.0.1",
            "arp.src.hw_mac": "00:00:00:00:00:99",
            "arp.dst.proto_ipv4": "10.0.0.2",
            "arp.dst.hw_mac": "00:00:00:00:00:02",
        }),
        _row({
            "frame.number": "7",
            "frame.time_epoch": "1003.0",
            "frame.len": "300",
            "frame.protocols": "eth:ip:udp:dhcp",
            "eth.src": "00:00:00:00:00:01",
            "eth.dst": "ff:ff:ff:ff:ff:ff",
            "ip.src": "10.0.0.1",
            "ip.dst": "255.255.255.255",
            "udp.srcport": "67",
            "udp.dstport": "68",
        }),
        _row({
            "frame.number": "8",
            "frame.time_epoch": "1004.0",
            "frame.len": "100",
            "frame.protocols": "eth:ip:udp:llmnr",
            "eth.src": "00:00:00:00:00:02",
            "eth.dst": "01:00:5e:00:00:fc",
            "ip.src": "10.0.0.2",
            "ip.dst": "224.0.0.252",
            "udp.srcport": "5355",
            "udp.dstport": "5355",
            "vlan.id": "20",
        }),
    ]

    document = TrafficAnalyzer().analyze_tsv(
        rows,
        source={"capture_job_id": "capture-1", "interface": "eth0"},
    )

    assert document["schema"] == "traffic-analysis"
    assert document["summary"]["frame_count"] == 8
    assert document["summary"]["byte_count"] == 940
    assert document["summary"]["duration_seconds"] == 4.0
    assert document["summary"]["vlan_ids"] == ["20"]
    assert document["tcp"]["packets"] == 2
    assert document["tcp"]["retransmissions"] == 1
    assert document["tcp"]["resets"] == 1
    assert document["dns"]["nxdomain"] == 1
    assert document["arp"]["conflict_count"] == 1
    assert document["arp"]["gratuitous_arp"] == 1
    assert document["dhcp"]["server_hints"][0]["endpoint"] == "10.0.0.1"
    assert document["broadcast_multicast"]["broadcast_frames"] >= 1
    assert document["broadcast_multicast"]["multicast_frames"] == 1
    assert document["communications_graph"]["edges"]
    titles = {item["title"] for item in document["observations"]}
    assert "Наблюдался обычный HTTP" in titles
    assert "Наблюдался LLMNR" in titles
    assert any("несколькими MAC" in title for title in titles)

    text = render_text(document)
    markdown = render_markdown(document)
    assert "АНАЛИЗ СЕТЕВОГО ТРАФИКА" in text
    assert "Что это может означать" in text
    assert "TOP TALKERS" in text
    assert "# WireScope — анализ сетевого трафика" in markdown
    assert "## TCP health" in markdown


def _finished_capture(api_context):
    app, service, evidence, _environment = api_context
    audit = service.create_audit(
        profile="packet_capture",
        interface="eth0",
        scope={"filter": None},
        actor="auditor",
    )
    job = service.create_job(
        audit_id=audit.id,
        job_type="packet_capture",
        target="eth0",
        parameters={"interface": "eth0"},
        resource_key="interface:eth0",
        resource_group="packet_capture",
        resource_limit=1,
    )
    claimed = service.claim_next("test-worker")
    assert claimed is not None and claimed.id == job.id
    pcap = evidence.put_bytes(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="packet_capture",
        payload=b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20),
        content_type="application/vnd.tcpdump.pcap",
        extension=".pcap",
        retention_class=RetentionClass.AUDIT,
    )
    result = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="packet_capture_result",
        document={
            "schema": "packet-capture-result",
            "schema_version": 1,
            "pcap_artifact_id": pcap.id,
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="packet-capture-result",
        schema_version=1,
    )
    service.cancel_running_job(
        job.id,
        message="Operator stopped capture",
        result_reference=result.id,
        summary={"pcap_artifact_id": pcap.id, "pcap_bytes": pcap.size},
    )
    return app, service, job.id


def test_stopped_capture_can_enqueue_idempotent_traffic_analysis(api_context):
    app, service, capture_job_id = _finished_capture(api_context)

    forbidden = request(
        app,
        "POST",
        f"/api/v1/captures/{capture_job_id}/analyze",
        as_role="viewer",
    )
    assert forbidden.status_code == 403

    accepted = request(app, "POST", f"/api/v1/captures/{capture_job_id}/analyze")
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]
    queued = service.get_job(job_id)
    assert queued.type == "traffic_analysis"
    assert queued.status.value == "queued"
    assert queued.parameters["source_capture_job_id"] == capture_job_id

    repeated = request(app, "POST", f"/api/v1/captures/{capture_job_id}/analyze")
    assert repeated.status_code == 202
    assert repeated.json()["job_id"] == job_id


def test_worker_registry_contains_traffic_analysis():
    assert "traffic_analysis" in build_registry().job_types
