from engine.passive_models import ConfidenceLevel
from findings.models import FindingDraft, Severity
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.models import RetentionClass
from jobs.service import JobService
from parsers.nmap import parse_nmap_xml
from reports.store import ReportStore
from tests.fixtures.nmap import fixture_path


def test_report_history_is_retained(database, durable_settings, evidence_store):
    jobs = JobService(database)
    audit = jobs.create_audit(profile="standard", interface="eth0", scope={})
    inventory = InventoryService(database, durable_settings, evidence_store)
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    service = next(
        item
        for item in inventory.list_services(
            audit_id=audit.id,
            limit=10,
            offset=0,
        ).items
        if item.port == 22
    )
    FindingStore(database).upsert_evaluation(
        audit_id=audit.id,
        drafts=[
            FindingDraft(
                rule_id="WS-SSH-WEAK-ALGORITHMS",
                rule_version="1",
                family="ssh",
                title="Weak SSH algorithms are offered",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                asset_id=service.asset_id,
                service_id=service.id,
                description="Weak algorithms were observed.",
                rationale="ssh_algorithms listed weak ciphers.",
                recommendation="Disable legacy algorithms.",
                data={},
                observation_ids=["obs-1"],
                evidence_artifact_ids=[],
                dedupe_key=f"{service.asset_id}:{service.id}",
            )
        ],
    )
    json_one = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_json",
        document={"schema": "audit-report", "schema_version": 1},
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report",
        schema_version=1,
    )
    html_one = evidence_store.put_bytes(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_html",
        payload=b"<html></html>",
        content_type="text/html; charset=utf-8",
        extension=".html",
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report-html",
        schema_version=1,
    )
    json_two = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_json",
        document={"schema": "audit-report", "schema_version": 1, "n": 2},
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report",
        schema_version=1,
    )
    html_two = evidence_store.put_bytes(
        audit_id=audit.id,
        job_id=None,
        artifact_type="audit_report_html",
        payload=b"<html>two</html>",
        content_type="text/html; charset=utf-8",
        extension=".html",
        retention_class=RetentionClass.REPORT,
        schema_name="audit-report-html",
        schema_version=1,
    )
    store = ReportStore(database)
    first = store.create(
        audit_id=audit.id,
        job_id=None,
        actor="auditor",
        source_hash="a" * 64,
        summary={"n": 1},
        json_artifact_id=json_one.id,
        html_artifact_id=html_one.id,
    )
    second = store.create(
        audit_id=audit.id,
        job_id=None,
        actor="auditor",
        source_hash="b" * 64,
        summary={"n": 2},
        json_artifact_id=json_two.id,
        html_artifact_id=html_two.id,
    )
    page = store.list_reports(audit_id=audit.id, limit=10, offset=0)
    assert page.total == 2
    assert [item.id for item in page.items] == [second.id, first.id]
    loaded = store.get(audit.id, first.id)
    assert loaded.source_hash == "a" * 64
    assert loaded.json_artifact_id == json_one.id
