from jobs.models import RetentionClass
from tests.helpers import http_request as request
from traffic_analysis.compare import compare_traffic_analysis, render_comparison_text
from traffic_analysis.latency import FIELDS as RTT_FIELDS, TcpLatencyAnalyzer


def _rtt_row(values: dict[str, str]) -> str:
    return "\t".join(values.get(field, "") for field in RTT_FIELDS) + "\n"


def test_tcp_ack_rtt_is_aggregated_only_from_observed_samples():
    rows = [
        _rtt_row({
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.stream": "1",
            "tcp.analysis.ack_rtt": "0.010",
        }),
        _rtt_row({
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.2",
            "tcp.stream": "1",
            "tcp.analysis.ack_rtt": "0.020",
        }),
        _rtt_row({
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.stream": "1",
            "tcp.analysis.ack_rtt": "0.030",
        }),
        _rtt_row({
            "ip.src": "10.0.0.2",
            "ip.dst": "10.0.0.10",
            "tcp.stream": "1",
            "tcp.analysis.ack_rtt": "",
        }),
    ]
    result = TcpLatencyAnalyzer().analyze_tsv(rows)
    assert result["status"] == "measured"
    assert result["overall"]["samples"] == 3
    assert result["overall"]["p50_ms"] == 20.0
    assert result["overall"]["max_ms"] == 30.0
    assert result["top_pairs"][0]["endpoint_a"] == "10.0.0.10"
    assert result["top_pairs"][0]["endpoint_b"] == "10.0.0.2"


def _document(*, endpoint: str, edge: tuple[str, str], multicast: float, rtt: float, warning: str | None):
    observations = [] if warning is None else [{"severity": "warning", "title": warning}]
    return {
        "analyzer_version": 5,
        "source": {"capture_job_id": f"capture-{endpoint}"},
        "summary": {
            "frame_count": 100,
            "byte_count": 10000,
            "duration_seconds": 60,
            "conversation_count": 1,
        },
        "protocol_distribution": [
            {"name": "tls", "frames": 60, "percent": 60.0},
            {"name": "mdns", "frames": 10, "percent": 10.0},
        ],
        "communications_graph": {
            "nodes": [{"id": "10.0.0.2"}, {"id": endpoint}],
            "edges": [{"endpoint_a": edge[0], "endpoint_b": edge[1]}],
        },
        "tcp": {
            "packets": 60,
            "retransmission_percent": 1.0,
            "lost_segments": 1,
            "zero_window": 0,
            "resets": 0,
        },
        "protocol_intelligence": {
            "dns": {"queries": 5, "responses": 5, "error_responses": 0},
        },
        "tcp_latency": {
            "status": "measured",
            "overall": {"samples": 10, "p50_ms": rtt / 2, "p95_ms": rtt, "max_ms": rtt * 1.2},
        },
        "broadcast_multicast": {"broadcast_percent": 2.0, "multicast_percent": multicast},
        "observations": observations,
    }


def test_comparison_highlights_nodes_edges_rtt_and_diagnostics():
    baseline = _document(
        endpoint="10.0.0.10",
        edge=("10.0.0.2", "10.0.0.10"),
        multicast=10.0,
        rtt=40.0,
        warning="Old warning",
    )
    current = _document(
        endpoint="10.0.0.20",
        edge=("10.0.0.2", "10.0.0.20"),
        multicast=30.0,
        rtt=120.0,
        warning="New warning",
    )
    comparison = compare_traffic_analysis(
        baseline=baseline,
        current=current,
        baseline_job_id="baseline-job",
        current_job_id="current-job",
    )
    assert comparison["network"]["new_endpoints"] == ["10.0.0.20"]
    assert comparison["network"]["missing_endpoints"] == ["10.0.0.10"]
    assert comparison["rtt"]["p95_ms"]["delta"] == 80.0
    assert comparison["broadcast_multicast"]["multicast_percent"]["delta"] == 20.0
    assert comparison["diagnostics"]["new_warning_titles"] == ["New warning"]
    text = render_comparison_text(comparison)
    assert "СРАВНЕНИЕ ДВУХ PCAP-АНАЛИЗОВ" in text
    assert "TCP ACK RTT p95" in text
    assert "Новые endpoints" in text


def _completed_analysis(api_context, *, interface: str, document: dict):
    app, service, evidence, _environment = api_context
    audit = service.create_audit(
        profile="packet_capture",
        interface=interface,
        scope={"filter": None},
        actor="auditor",
    )
    job = service.create_job(
        audit_id=audit.id,
        job_type="traffic_analysis",
        target="capture-source",
        parameters={
            "source_capture_job_id": "capture-source",
            "pcap_artifact_id": "pcap-source",
            "analyzer_version": 5,
        },
        resource_group="traffic_analysis",
        resource_limit=1,
    )
    claimed = service.claim_next("test-worker")
    assert claimed is not None and claimed.id == job.id
    artifact = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="traffic_analysis_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="traffic-analysis",
        schema_version=1,
    )
    service.complete_job(job.id, result_reference=artifact.id)
    return app, service.get_job(job.id)


def test_compare_api_lists_completed_analyses_and_returns_text(api_context):
    baseline_doc = _document(
        endpoint="10.0.0.10",
        edge=("10.0.0.2", "10.0.0.10"),
        multicast=5.0,
        rtt=30.0,
        warning=None,
    )
    current_doc = _document(
        endpoint="10.0.0.20",
        edge=("10.0.0.2", "10.0.0.20"),
        multicast=25.0,
        rtt=90.0,
        warning="New warning",
    )
    app, baseline = _completed_analysis(api_context, interface="eth0", document=baseline_doc)
    _app, current = _completed_analysis(api_context, interface="eth1", document=current_doc)

    page = request(app, "GET", "/api/v1/traffic-analysis?limit=10")
    assert page.status_code == 200, page.text
    ids = {item["job_id"] for item in page.json()["items"]}
    assert {baseline.id, current.id}.issubset(ids)

    compared = request(
        app,
        "GET",
        f"/api/v1/jobs/{current.id}/traffic-analysis/compare?against={baseline.id}",
    )
    assert compared.status_code == 200, compared.text
    assert compared.json()["rtt"]["p95_ms"]["delta"] == 60.0

    text = request(
        app,
        "GET",
        f"/api/v1/jobs/{current.id}/traffic-analysis/compare?against={baseline.id}&format=text",
    )
    assert text.status_code == 200
    assert "СРАВНЕНИЕ ДВУХ PCAP-АНАЛИЗОВ" in text.text


def test_traffic_comparison_ui_and_cache_bust_are_present(api_context):
    app, _service, _evidence, _environment = api_context
    root = request(app, "GET", "/", as_role=None)
    assert root.status_code == 200
    assert "traffic_analysis.js?v=20260825-ui9" in root.text
    assert "traffic_analysis.css?v=20260825-ui9" in root.text

    static_js = request(app, "GET", "/static/traffic_analysis.js", as_role=None)
    assert static_js.status_code == 200
    assert "Сравнить с другим PCAP-анализом" in static_js.text
    assert "/traffic-analysis?limit=50" in static_js.text
