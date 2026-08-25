from types import SimpleNamespace

from jobs.models import RetentionClass
from topology.source_health import decorate_source_health


def _artifact(
    evidence_store,
    *,
    audit_id: str,
    artifact_type: str,
    schema_name: str,
    job_id: str | None = None,
):
    return evidence_store.put_json(
        audit_id=audit_id,
        job_id=job_id,
        artifact_type=artifact_type,
        document={"schema": schema_name, "schema_version": 1},
        retention_class=RetentionClass.AUDIT,
        schema_name=schema_name,
        schema_version=1,
    )


def test_source_health_marks_persisted_but_unused_enrichment_artifact_partial(
    job_service,
    evidence_store,
    database,
):
    audit = job_service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    route = _artifact(
        evidence_store,
        audit_id=audit.id,
        artifact_type="route_trace_result",
        schema_name="route-trace-result",
    )
    snmp_job = job_service.create_job(
        audit_id=audit.id,
        job_type="snmp_topology",
        target="192.0.2.1",
        parameters={"target": "192.0.2.1"},
    )
    snmp = _artifact(
        evidence_store,
        audit_id=audit.id,
        job_id=snmp_job.id,
        artifact_type="snmp_topology_result",
        schema_name="snmp-topology-result",
    )
    services = SimpleNamespace(database=database)
    topology = {
        "summary": {},
        "warnings": [],
        "upstream": {"artifact_ids": [route.id]},
        "snmp_topology": {"artifact_ids": []},
    }

    result = decorate_source_health(services, topology, audit_ids=[audit.id])

    assert result["partial"] is True
    assert result["summary"]["source_errors"] == 1
    assert result["source_errors"] == [
        {
            "audit_id": audit.id,
            "artifact_id": snmp.id,
            "artifact_type": "snmp_topology_result",
            "component": "snmp-topology",
            "code": "artifact_unavailable",
            "schema_name": "snmp-topology-result",
            "schema_version": 1,
        }
    ]
    assert any("Topology неполная" in warning for warning in result["warnings"])


def test_source_health_does_not_guess_about_unused_jobless_snmp_artifact(
    job_service,
    evidence_store,
    database,
):
    audit = job_service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    _artifact(
        evidence_store,
        audit_id=audit.id,
        artifact_type="snmp_topology_result",
        schema_name="snmp-topology-result",
    )
    services = SimpleNamespace(database=database)
    topology = {
        "summary": {},
        "warnings": [],
        "upstream": {"artifact_ids": []},
        "snmp_topology": {"artifact_ids": []},
    }

    result = decorate_source_health(services, topology, audit_ids=[audit.id])

    assert result["partial"] is False
    assert result["source_errors"] == []


def test_source_health_preserves_existing_global_source_errors(
    job_service,
    database,
):
    audit = job_service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    services = SimpleNamespace(database=database)
    existing = {
        "audit_id": "broken-audit",
        "component": "topology",
        "code": "source_unavailable",
        "error_type": "RuntimeError",
    }
    topology = {
        "partial": True,
        "source_errors": [existing],
        "summary": {"source_errors": 1},
        "warnings": [],
        "upstream": {"artifact_ids": []},
        "snmp_topology": {"artifact_ids": []},
    }

    result = decorate_source_health(services, topology, audit_ids=[audit.id])

    assert result["partial"] is True
    assert result["source_errors"] == [existing]
    assert result["summary"]["source_errors"] == 1
