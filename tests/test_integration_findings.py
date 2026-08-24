from engine.active_profiles import profile_for
from engine.passive_models import ConfidenceLevel
from engine.scope import ActiveProfile, ScopeValidator
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.handlers.findings import FindingsEvaluationHandler
from jobs.models import JobStatus, RetentionClass
from jobs.registry import HandlerRegistry
from jobs.service import JobService
from jobs.worker import JobWorker
from parsers.nmap import parse_nmap_xml
from persistence.database import Database
from protocol_audits.models import ObservationDraft
from protocol_audits.store import ProtocolObservationStore
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
        document=parse_nmap_xml(fixture_path("protocol_host.xml")),
    )
    services = {
        item.port: item
        for item in inventory.list_services(
            audit_id=audit_id,
            limit=50,
            offset=0,
        ).items
    }
    store = ProtocolObservationStore(database)
    store.upsert_many(
        audit_id=audit_id,
        asset_id=services[22].asset_id,
        service_id=services[22].id,
        protocol="ssh",
        module="ssh",
        drafts=[
            ObservationDraft(
                kind="ssh_algorithms",
                data={
                    "kex": ["curve25519-sha256"],
                    "host_key": ["ssh-ed25519"],
                    "encryption": ["chacha20-poly1305@openssh.com"],
                    "mac": ["hmac-sha2-256"],
                },
                confidence=ConfidenceLevel.HIGH,
                source="ssh-audit",
            )
        ],
        evidence_artifact_id=None,
    )
    store.upsert_many(
        audit_id=audit_id,
        asset_id=services[443].asset_id,
        service_id=services[443].id,
        protocol="tls",
        module="tls",
        drafts=[
            ObservationDraft(
                kind="tls_session",
                data={"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
                confidence=ConfidenceLevel.HIGH,
                source="openssl",
            ),
            ObservationDraft(
                kind="tls_certificate",
                data={
                    "subject": "CN = linux.example.test",
                    "not_after": "Jan 1 00:00:00 2027 GMT",
                    "verify_code": 18,
                    "verify_message": "self signed certificate",
                },
                confidence=ConfidenceLevel.HIGH,
                source="openssl",
            ),
        ],
        evidence_artifact_id="tls-evidence",
    )
    store.upsert_many(
        audit_id=audit_id,
        asset_id=services[445].asset_id,
        service_id=services[445].id,
        protocol="smb",
        module="smb",
        drafts=[
            ObservationDraft(
                kind="smb_null_session",
                data={"accepted": True, "share_count": 2, "shares": []},
                confidence=ConfidenceLevel.HIGH,
                source="smbclient",
            )
        ],
        evidence_artifact_id="smb-evidence",
    )
    store.upsert_many(
        audit_id=audit_id,
        asset_id=services[161].asset_id,
        service_id=services[161].id,
        protocol="snmp",
        module="snmp",
        drafts=[
            ObservationDraft(
                kind="snmp_unauthenticated",
                data={"responded": False, "auth": "none", "version": "3"},
                confidence=ConfidenceLevel.MEDIUM,
                source="snmpget",
            )
        ],
        evidence_artifact_id=None,
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
    return inventory


def test_findings_job_persists_results_and_survives_restart(
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    audit = job_service.create_audit(
        profile="standard",
        interface="eth0",
        scope={},
    )
    _seed(database, durable_settings, evidence_store, audit.id)
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="findings_evaluation",
        target="eth0",
        resource_key=f"audit:{audit.id}",
        resource_group="findings",
        resource_limit=1,
    )
    registry = HandlerRegistry()
    registry.register("findings_evaluation", FindingsEvaluationHandler())
    worker = JobWorker(
        worker_id="findings-worker",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )
    worker.run_once()
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    result = evidence_store.read_json(job_service.artifact(completed.result_reference))
    assert result["schema"] == "findings-result"
    assert result["summary"]["findings"] >= 3

    store = FindingStore(database)
    page = store.list_findings(audit_id=audit.id, limit=50, offset=0)
    rule_ids = {item.rule_id for item in page.items}
    assert "WS-TLS-CERT-UNTRUSTED" in rule_ids
    assert "WS-SMB-NULL-SESSION" in rule_ids
    assert "WS-MGMT-INSECURE-PROTOCOL" in rule_ids
    assert "WS-INFRA-LLMNR" in rule_ids
    assert "WS-SNMP-UNAUTHENTICATED" not in rule_ids
    assert "WS-SSH-WEAK-ALGORITHMS" not in rule_ids
    protocol_findings = [
        item
        for item in page.items
        if item.rule_id in {"WS-TLS-CERT-UNTRUSTED", "WS-SMB-NULL-SESSION"}
    ]
    assert all(item.observation_ids for item in protocol_findings)
    assert all(item.rationale for item in page.items)

    restarted_db = Database(durable_settings)
    try:
        restarted_jobs = JobService(restarted_db)
        persisted = restarted_jobs.get_job(job.id)
        assert persisted.status == JobStatus.COMPLETED
        restarted_store = FindingStore(restarted_db)
        assert restarted_store.count(audit.id) == page.total
    finally:
        restarted_db.dispose()
