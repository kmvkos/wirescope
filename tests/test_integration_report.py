from engine.active_profiles import profile_for
from engine.passive_models import ConfidenceLevel
from engine.scope import ActiveProfile, ScopeValidator
from findings.copy import SSH_WEAK
from findings.models import FindingDraft, Severity
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.handlers.report import ReportGenerationHandler
from jobs.models import JobStatus, RetentionClass
from jobs.registry import HandlerRegistry
from jobs.service import JobService
from jobs.worker import JobWorker
from parsers.nmap import parse_nmap_xml
from persistence.database import Database
from reports.store import ReportStore
from tests.fixtures.nmap import fixture_path


def _seed(database, settings, evidence_store, audit_id):
    inventory = InventoryService(database, settings, evidence_store)
    scope = ScopeValidator(settings).validate(
        ["192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    inventory.confirm_scope(
        audit_id=audit_id,
        scope=scope,
        interface="eth0",
        route_context={"interface": "eth0"},
        timing_policy=profile_for(ActiveProfile.STANDARD, settings).timing,
    )
    inventory.ingest_nmap_document(
        audit_id=audit_id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    service = next(
        item
        for item in inventory.list_services(
            audit_id=audit_id,
            limit=50,
            offset=0,
        ).items
        if item.port == 22
    )
    FindingStore(database).upsert_evaluation(
        audit_id=audit_id,
        drafts=[
            FindingDraft(
                rule_id="WS-SSH-WEAK-ALGORITHMS",
                rule_version="1",
                family="ssh",
                title=SSH_WEAK["title"],
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                asset_id=service.asset_id,
                service_id=service.id,
                description=SSH_WEAK["description"],
                rationale="ssh_algorithms listed weak ciphers.",
                recommendation=SSH_WEAK["recommendation"],
                data={"weak_algorithms": {"kex": ["diffie-hellman-group1-sha1"]}},
                observation_ids=["obs-1"],
                evidence_artifact_ids=[],
                dedupe_key=f"{service.asset_id}:{service.id}",
            )
        ],
    )
    nmap_xml = evidence_store.put_bytes(
        audit_id=audit_id,
        job_id=None,
        artifact_type="nmap_xml",
        payload=b"<nmaprun>secret-tool-output</nmaprun>",
        content_type="application/xml",
        extension=".xml",
        retention_class=RetentionClass.AUDIT,
    )
    evidence_store.put_json(
        audit_id=audit_id,
        job_id=None,
        artifact_type="passive_result",
        document={
            "schema": "passive-result",
            "schema_version": 1,
            "result": {
                "sensors": {
                    "llmnr": {"status": "detected", "hits": 4},
                    "nbns": {"status": "absent", "hits": 0},
                }
            },
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="passive-result",
        schema_version=1,
    )
    return inventory, nmap_xml


def test_report_job_reproduces_from_persisted_data(
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    audit = job_service.create_audit(
        profile="standard",
        interface="eth0",
        scope={"site": "lab"},
    )
    snapshot = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="environment_snapshot",
        document={
            "schema": "environment-snapshot",
            "schema_version": 1,
            "environment": {
                "hostname": "wirescope-test",
                "interfaces": [
                    {
                        "name": "eth0",
                        "state": "UP",
                        "mac": "00:11:22:33:44:55",
                        "ipv4": ["192.0.2.10/24"],
                        "ipv6": [],
                    }
                ],
                "default_route": {"gateway": "192.0.2.1", "interface": "eth0"},
                "dns": ["192.0.2.53"],
            },
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="environment-snapshot",
        schema_version=1,
    )
    job_service.set_environment_reference(audit.id, snapshot.id)
    audit = job_service.get_audit(audit.id)
    _seed(database, durable_settings, evidence_store, audit.id)

    job = job_service.create_job(
        audit_id=audit.id,
        job_type="report_generation",
        target="eth0",
        parameters={"actor": "auditor"},
        resource_key=f"audit:{audit.id}",
        resource_group="report",
        resource_limit=1,
    )
    second = job_service.create_job(
        audit_id=audit.id,
        job_type="report_generation",
        target="eth0",
        parameters={"actor": "auditor"},
        resource_key=f"audit:{audit.id}",
        resource_group="report",
        resource_limit=1,
    )
    registry = HandlerRegistry()
    registry.register("report_generation", ReportGenerationHandler())
    worker = JobWorker(
        worker_id="report-worker",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )
    worker.run_once()
    worker.run_once()
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    assert job_service.get_job(second.id).status == JobStatus.COMPLETED
    result = evidence_store.read_json(
        job_service.artifact(completed.result_reference)
    )
    assert result["schema"] == "report-result"
    store = ReportStore(database)
    report = store.get(audit.id, result["report_id"])
    document = evidence_store.read_json(
        job_service.artifact(report.json_artifact_id)
    )
    html = evidence_store.read_bytes(
        job_service.artifact(report.html_artifact_id)
    ).decode("utf-8")
    assert document["schema"] == "audit-report"
    assert document["executive_summary"]["open_finding_count"] == 1
    assert document["scope"]["confirmed"] is True
    assert document["environment"]["hostname"] == "wirescope-test"
    assert "llmnr" in document["executive_summary"]["detected_sensors"]
    assert all(
        "relative_path" not in item
        for item in document["evidence_references"]
    )
    assert "secret-tool-output" not in html
    assert "<nmaprun>" not in html
    assert SSH_WEAK["title"] in html
    assert SSH_WEAK["recommendation"] in html
    assert "Результат аудита" in html
    assert "Обнаруженные проблемы" in html
    assert "Что обнаружено" in html
    assert "Почему это важно" in html
    assert "Что рекомендуется сделать" in html
    assert "Пассивное наблюдение" in html
    assert "VLAN ID считается наблюдаемым только при наличии тега 802.1Q" in html
    assert document["environment"]["capture_interface"] == "eth0"
    assert document["environment"]["had_l3_address"] is True
    assert document["passive"]["vlan_tag_note"].startswith("VLAN в кадре")
    json_path = evidence_store.path_for(
        job_service.artifact(report.json_artifact_id)
    )
    html_path = evidence_store.path_for(
        job_service.artifact(report.html_artifact_id)
    )
    assert json_path.is_relative_to(evidence_store.root)
    assert html_path.is_relative_to(evidence_store.root)

    listing = store.list_reports(audit_id=audit.id, limit=10, offset=0)
    assert listing.total == 2
    hashes = {item.source_hash for item in listing.items}
    assert len(hashes) == 1

    restarted_db = Database(durable_settings)
    try:
        restarted_jobs = JobService(restarted_db)
        persisted = restarted_jobs.get_job(job.id)
        assert persisted.status == JobStatus.COMPLETED
        restarted_store = ReportStore(restarted_db)
        assert restarted_store.list_reports(
            audit_id=audit.id,
            limit=10,
            offset=0,
        ).total == 2
    finally:
        restarted_db.dispose()
