from global_analysis.render import render_markdown, render_text
from jobs.models import RetentionClass
from jobs.worker import JobWorker, build_registry
from tests.helpers import http_request as request


def _setup_completed_traffic(api_context, *, marker="one"):
    app, service, evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={"targets": ["192.0.2.0/24"]},
        actor="auditor",
    )
    worker_id = f"traffic-history-{marker}"
    service.register_worker(worker_id)
    job = service.create_job(
        audit_id=audit.id,
        job_type="traffic_analysis",
        target="eth0",
        parameters={"source_capture_job_id": f"capture-{marker}"},
    )
    claimed = service.claim_next(worker_id)
    assert claimed is not None and claimed.id == job.id
    artifact = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="traffic_analysis_result",
        document={
            "schema": "traffic-analysis",
            "schema_version": 1,
            "analyzer_version": 5,
            "summary": {"frame_count": 4, "duration_seconds": 2.0},
            "communications_graph": {
                "nodes": [
                    {"id": "192.0.2.10", "kind": "ip"},
                    {"id": "8.8.8.8", "kind": "ip"},
                ],
                "edges": [
                    {
                        "endpoint_a": "192.0.2.10",
                        "endpoint_b": "8.8.8.8",
                        "packets": 4,
                        "bytes": 400,
                        "protocols": [{"name": "dns", "frames": 4}],
                        "ports": [{"port": "udp/53", "frames": 2}],
                        "confidence": "observed",
                    }
                ],
            },
            "protocol_intelligence": {
                "dns": {"servers": [{"endpoint": "8.8.8.8", "count": 2}]},
                "dhcp": {"servers": []},
            },
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="traffic-analysis",
        schema_version=1,
    )
    service.complete_job(
        job.id,
        result_reference=artifact.id,
        summary={"traffic_analysis_job_id": job.id},
    )
    return app, service, evidence, audit, service.get_job(job.id)


def _run_global(app, service, evidence, audit_id, traffic_job_id, *, rebuild_of=None):
    body = {"traffic_analysis_job_id": traffic_job_id}
    if rebuild_of:
        body["rebuild_of_job_id"] = rebuild_of
    accepted = request(
        app,
        "POST",
        f"/api/v1/audits/{audit_id}/global-analysis",
        json=body,
    )
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]
    worker = JobWorker(
        worker_id=f"ga-history-worker-{job_id[:8]}",
        service=service,
        registry=build_registry(),
        evidence_store=evidence,
        settings=app.state.settings,
    )
    assert worker.run_once() is True
    completed = service.get_job(job_id)
    assert completed.status.value == "completed", completed.error
    return completed


def test_global_analysis_history_read_and_exports_are_viewer_accessible(api_context):
    app, service, evidence, audit, traffic = _setup_completed_traffic(api_context)
    completed = _run_global(app, service, evidence, audit.id, traffic.id)

    history = request(
        app,
        "GET",
        f"/api/v1/audits/{audit.id}/global-analysis/history",
        as_role="viewer",
    )
    assert history.status_code == 200, history.text
    items = history.json()["items"]
    assert items[0]["job_id"] == completed.id
    assert items[0]["traffic_analysis_job_id"] == traffic.id
    assert items[0]["result_available"] is True
    assert isinstance(items[0]["summary"], dict)

    result = request(
        app,
        "GET",
        f"/api/v1/jobs/{completed.id}/global-analysis",
        as_role="viewer",
    )
    assert result.status_code == 200, result.text
    document = result.json()
    assert document["schema"] == "global-analysis"
    assert document["execution"]["job_id"] == completed.id
    assert document["execution"]["rebuild_of_job_id"] is None

    json_export = request(
        app,
        "GET",
        f"/api/v1/jobs/{completed.id}/global-analysis/export?format=json",
        as_role="viewer",
    )
    assert json_export.status_code == 200
    assert json_export.json()["schema"] == "global-analysis"

    text_export = request(
        app,
        "GET",
        f"/api/v1/jobs/{completed.id}/global-analysis/export?format=text",
        as_role="viewer",
    )
    assert text_export.status_code == 200
    assert "КОРРЕЛЯЦИЯ РЕЗУЛЬТАТОВ" in text_export.text
    assert "СОГЛАСОВАННОСТЬ ИНФРАСТРУКТУРНЫХ ДАННЫХ" in text_export.text

    md_export = request(
        app,
        "GET",
        f"/api/v1/jobs/{completed.id}/global-analysis/export?format=markdown",
        as_role="viewer",
    )
    assert md_export.status_code == 200
    assert "# WireScope — Корреляция результатов" in md_export.text


def test_global_analysis_rebuild_creates_new_immutable_result_with_lineage(api_context):
    app, service, evidence, audit, traffic = _setup_completed_traffic(api_context)
    first = _run_global(app, service, evidence, audit.id, traffic.id)
    first_artifact = service.artifact(first.result_reference)
    first_payload = evidence.read_bytes(first_artifact)

    rebuilt = _run_global(
        app,
        service,
        evidence,
        audit.id,
        traffic.id,
        rebuild_of=first.id,
    )
    assert rebuilt.id != first.id
    assert rebuilt.result_reference != first.result_reference
    assert rebuilt.parameters["rebuild_of_job_id"] == first.id
    assert rebuilt.parameters["traffic_analysis_job_id"] == traffic.id

    first_after = evidence.read_bytes(service.artifact(first.result_reference))
    assert first_after == first_payload

    rebuilt_document = evidence.read_json(service.artifact(rebuilt.result_reference))
    assert rebuilt_document["execution"]["job_id"] == rebuilt.id
    assert rebuilt_document["execution"]["rebuild_of_job_id"] == first.id

    history = request(
        app,
        "GET",
        f"/api/v1/audits/{audit.id}/global-analysis/history",
        as_role="viewer",
    ).json()["items"]
    assert [item["job_id"] for item in history[:2]] == [rebuilt.id, first.id]
    assert history[0]["rebuild_of_job_id"] == first.id


def test_global_analysis_rebuild_rejects_different_traffic_input(api_context):
    app, service, evidence, audit, traffic = _setup_completed_traffic(api_context)
    first = _run_global(app, service, evidence, audit.id, traffic.id)

    worker_id = "traffic-history-other"
    service.register_worker(worker_id)
    other = service.create_job(
        audit_id=audit.id,
        job_type="traffic_analysis",
        target="eth0",
        parameters={"source_capture_job_id": "capture-other"},
    )
    claimed = service.claim_next(worker_id)
    assert claimed is not None and claimed.id == other.id
    artifact = evidence.put_json(
        audit_id=audit.id,
        job_id=other.id,
        artifact_type="traffic_analysis_result",
        document={
            "schema": "traffic-analysis",
            "schema_version": 1,
            "communications_graph": {"nodes": [], "edges": []},
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="traffic-analysis",
        schema_version=1,
    )
    service.complete_job(other.id, result_reference=artifact.id, summary={})

    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/global-analysis",
        json={
            "traffic_analysis_job_id": other.id,
            "rebuild_of_job_id": first.id,
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "global_analysis_rebuild_input_mismatch"


def test_global_analysis_renderers_are_bounded_human_readable_views():
    document = {
        "schema": "global-analysis",
        "schema_version": 1,
        "generated_at": "2026-08-27T08:00:00Z",
        "partial": False,
        "network_io": False,
        "audit": {"id": "audit-1", "profile": "deep", "interface": "eth0"},
        "inputs": {"traffic_analysis_job_id": "traffic-1"},
        "summary": {
            "inventory_assets": 2,
            "inventory_assets_observed_in_traffic": 1,
            "inventory_assets_not_observed_in_traffic": 1,
            "traffic_endpoints": 3,
            "unmatched_traffic_endpoints": 2,
            "services": 4,
            "services_observed_in_traffic": 1,
            "findings": 2,
            "external_communications": 1,
        },
        "operator_summary": {
            "headline": "Корреляция результатов",
            "lines": ["С выбранным PCAP сопоставлен один asset."],
        },
        "infrastructure_consistency": {
            "gateway": {"status": "consistent", "rule_id": "GA-GATEWAY-CONSISTENCY-001", "sources": {"environment": ["192.0.2.1"], "topology": ["192.0.2.1"]}, "common_values": ["192.0.2.1"]},
            "dhcp": {"status": "insufficient", "rule_id": "GA-DHCP-CONSISTENCY-001", "sources": {}, "common_values": []},
            "dns": {"status": "divergent", "rule_id": "GA-DNS-CONSISTENCY-001", "sources": {"environment": ["192.0.2.53"], "traffic": ["8.8.8.8"]}, "common_values": []},
        },
        "finding_traffic_relevance": [
            {"traffic_relevance": "service_traffic_observed"},
            {"traffic_relevance": "uncorrelated"},
        ],
        "external_communications": [
            {"asset_id": "asset-1", "external_endpoint": "8.8.8.8", "packets": 20, "bytes": 2048, "protocols": [{"name": "dns"}], "ports": [{"port": "udp/53"}]},
        ],
        "warnings": ["pair-level service correlation"],
    }
    text = render_text(document)
    markdown = render_markdown(document)
    assert "КОРРЕЛЯЦИЯ РЕЗУЛЬТАТОВ" in text
    assert "8.8.8.8" in text
    assert "DNS: расхождение" in text
    assert "## Internal assets ↔ global endpoints" in markdown
    assert "8.8.8.8" in markdown


def test_root_html_loads_global_analysis_workspace_assets(api_context):
    app, _service, _evidence, _environment = api_context
    response = request(app, "GET", "/", auth=False)
    assert response.status_code == 200
    assert "/static/global_analysis.css?v=20260827-ui19" in response.text
    assert "/static/global_analysis.js?v=20260827-ui19" in response.text
