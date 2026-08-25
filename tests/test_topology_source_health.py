from types import SimpleNamespace

from jobs.models import RetentionClass
from topology.source_health import decorate_source_health


def _artifact(evidence_store, *, audit_id: str, artifact_type: str, schema_name: str):
    return evidence_store.put_json(
        audit_id=audit_id,
        job_id=None,
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
    snmp = _artifact(
        evidence_store,
        audit_id=audit.id,
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
