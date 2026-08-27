from copy import deepcopy

from global_analysis.enrich import enrich_global_analysis
from jobs.models import RetentionClass
from jobs.worker import JobWorker, build_registry
from tests.helpers import http_request as request


def _base_document():
    return {
        "schema": "global-analysis",
        "schema_version": 1,
        "audit": {"id": "audit-1", "interface": "eth0"},
        "inputs": {
            "traffic_analysis_job_id": "traffic-1",
            "traffic_result_reference": "traffic-artifact",
        },
        "summary": {
            "inventory_assets": 1,
            "inventory_assets_observed_in_traffic": 1,
            "services_observed_in_traffic": 1,
            "external_communications": 1,
        },
        "asset_traffic_identity": [
            {"asset_id": "asset-1", "endpoint": "10.0.0.10"},
        ],
        "service_usage": [
            {"asset_id": "asset-1", "service_id": "service-1"},
        ],
        "finding_traffic_relevance": [
            {"finding_id": "finding-1", "asset_id": "asset-1", "service_id": "service-1"},
        ],
        "external_communications": [
            {"asset_id": "asset-1", "external_endpoint": "8.8.8.8"},
        ],
        "partial": False,
    }


def _infrastructure_inputs():
    environment = {
        "default_routes": [{"interface": "eth0", "gateway": "10.0.0.1"}],
        "dhcp_leases": [
            {
                "interface": "eth0",
                "routers": ["10.0.0.1"],
                "dns": ["10.0.0.53"],
                "server_address": "10.0.0.2",
            }
        ],
        "dns": ["127.0.0.53"],
    }
    passive = {
        "dhcp": {
            "routers": ["10.0.0.1"],
            "servers": ["10.0.0.2"],
        }
    }
    topology = {
        "schema": "network-topology",
        "schema_version": 3,
        "partial": False,
        "nodes": [
            {"roles": ["gateway"], "addresses": ["10.0.0.1"]},
            {"roles": ["dns"], "addresses": ["10.0.0.53"]},
        ],
        "upstream": {"artifact_ids": ["route-artifact"]},
        "source_errors": [],
    }
    traffic = {
        "protocol_intelligence": {
            "dhcp": {"servers": [{"endpoint": "10.0.0.2", "count": 3}]},
            "dns": {"servers": [{"endpoint": "10.0.0.53", "count": 20}]},
        }
    }
    return environment, passive, topology, traffic


def test_infrastructure_consistency_matches_gateway_dhcp_and_dns_sources():
    environment, passive, topology, traffic = _infrastructure_inputs()
    data = enrich_global_analysis(
        _base_document(),
        environment=environment,
        passive=passive,
        topology=topology,
        traffic_analysis=traffic,
        evidence_references=[
            {"id": "traffic-artifact", "artifact_type": "traffic_analysis_result"},
            {"id": "route-artifact", "artifact_type": "route_trace_result"},
        ],
    )

    consistency = data["infrastructure_consistency"]
    assert consistency["gateway"]["status"] == "consistent"
    assert consistency["gateway"]["common_values"] == ["10.0.0.1"]
    assert consistency["dhcp"]["status"] == "consistent"
    assert consistency["dhcp"]["common_values"] == ["10.0.0.2"]
    assert consistency["dns"]["status"] == "consistent"
    assert consistency["dns"]["common_values"] == ["10.0.0.53"]
    assert data["evidence_references"]["traffic_analysis"]["artifact_id"] == "traffic-artifact"
    assert data["evidence_references"]["topology"]["artifact_ids"] == ["route-artifact"]
    assert data["asset_traffic_identity"][0]["evidence_refs"]
    assert data["operator_summary"]["lines"]


def test_infrastructure_consistency_reports_divergence_without_making_document_partial():
    environment, passive, topology, traffic = _infrastructure_inputs()
    traffic = deepcopy(traffic)
    traffic["protocol_intelligence"]["dns"]["servers"] = [{"endpoint": "8.8.8.8", "count": 20}]

    data = enrich_global_analysis(
        _base_document(),
        environment=environment,
        passive=passive,
        topology=topology,
        traffic_analysis=traffic,
        evidence_references=[],
    )
    assert data["infrastructure_consistency"]["dns"]["status"] == "divergent"
    assert data["partial"] is False
    assert data["summary"]["infrastructure_consistency_divergent"] == 1
    assert any("dns" in line for line in data["operator_summary"]["lines"])


def _completed_traffic_job(api_context):
    app, service, evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={"targets": ["192.0.2.0/24"]},
        actor="auditor",
    )
    service.register_worker("traffic-setup")
    job = service.create_job(
        audit_id=audit.id,
        job_type="traffic_analysis",
        target="eth0",
        parameters={"source_capture_job_id": "fixture-capture"},
    )
    claimed = service.claim_next("traffic-setup")
    assert claimed is not None and claimed.id == job.id
    artifact = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="traffic_analysis_result",
        document={
            "schema": "traffic-analysis",
            "schema_version": 1,
            "analyzer_version": 5,
            "summary": {"frame_count": 2, "duration_seconds": 1.0},
            "communications_graph": {
                "nodes": [
                    {"id": "192.0.2.10", "kind": "ip"},
                    {"id": "8.8.8.8", "kind": "ip"},
                ],
                "edges": [
                    {
                        "endpoint_a": "192.0.2.10",
                        "endpoint_b": "8.8.8.8",
                        "packets": 2,
                        "bytes": 200,
                        "protocols": [{"name": "dns", "frames": 2}],
                        "ports": [{"port": "udp/53", "frames": 1}],
                        "confidence": "observed",
                    }
                ],
            },
            "protocol_intelligence": {
                "dns": {"servers": [{"endpoint": "8.8.8.8", "count": 1}]},
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
    return app, service, evidence, audit, service.get_job(job.id), artifact


def test_global_analysis_post_is_auditor_only_and_enqueues_durable_job(api_context):
    app, service, _evidence, audit, traffic_job, _artifact = _completed_traffic_job(api_context)
    url = f"/api/v1/audits/{audit.id}/global-analysis"
    payload = {"traffic_analysis_job_id": traffic_job.id}

    forbidden = request(app, "POST", url, json=payload, as_role="viewer")
    assert forbidden.status_code == 403

    accepted = request(app, "POST", url, json=payload)
    assert accepted.status_code == 202, accepted.text
    queued = service.get_job(accepted.json()["job_id"])
    assert queued.type == "global_analysis"
    assert queued.parameters["traffic_analysis_job_id"] == traffic_job.id
    assert queued.resource_group == "global_analysis"


def test_global_analysis_worker_persists_canonical_artifact_and_namespaced_summary(api_context):
    app, service, evidence, audit, traffic_job, traffic_artifact = _completed_traffic_job(api_context)
    accepted = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/global-analysis",
        json={"traffic_analysis_job_id": traffic_job.id},
    )
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]

    worker = JobWorker(
        worker_id="global-analysis-worker",
        service=service,
        registry=build_registry(),
        evidence_store=evidence,
        settings=app.state.settings,
    )
    assert worker.run_once() is True

    completed = service.get_job(job_id)
    assert completed.status.value == "completed", completed.error
    artifact = service.artifact(completed.result_reference)
    assert artifact.artifact_type == "global_analysis_result"
    assert artifact.schema_name == "global-analysis"
    document = evidence.read_json(artifact)
    assert document["schema"] == "global-analysis"
    assert document["network_io"] is False
    assert "infrastructure_consistency" in document
    assert "operator_summary" in document
    assert document["evidence_references"]["traffic_analysis"]["artifact_id"] == traffic_artifact.id

    refreshed_audit = service.get_audit(audit.id)
    assert "global_analysis" in refreshed_audit.summary
    assert refreshed_audit.summary["global_analysis"]["result_reference"] == artifact.id


def test_worker_registry_contains_global_analysis():
    assert "global_analysis" in build_registry().job_types
