from pathlib import Path

from engine.active_profiles import profile_for
from engine.scope import ActiveProfile, ScopeValidator
from inventory.service import InventoryService
from jobs.handlers.protocol import ProtocolAuditHandler
from jobs.models import JobStatus
from jobs.registry import HandlerRegistry
from jobs.service import JobService
from jobs.worker import JobWorker
from parsers.nmap import parse_nmap_xml
from persistence.database import Database
from protocol_audits.store import ProtocolObservationStore
from storage.evidence import EvidenceStore
from tests.fixtures.nmap import fixture_path
from tests.fixtures.protocol import fixture_text
from tests.helpers import ProtocolRecordingRunner


def _seed_inventory(database, settings, evidence_store, audit_id):
    inventory = InventoryService(database, settings, evidence_store)
    scope = ScopeValidator(settings).validate(
        ["192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    confirmed = inventory.confirm_scope(
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
    return inventory, confirmed


def _fake_locate(missing=()):
    skipped = set(missing)

    def locate(tool: str) -> str | None:
        name = Path(tool).name
        if name in skipped:
            return None
        return f"/usr/bin/{name}"

    return locate


def _outputs():
    return {
        "ssh-audit": fixture_text("ssh-audit.json"),
        "openssl": fixture_text("openssl-s_client.txt"),
        "curl": fixture_text("curl-http.txt"),
        "dig": [
            fixture_text("dig-version.txt"),
            fixture_text("dig-id.txt"),
        ],
        "smbclient": fixture_text("smbclient-denied.txt"),
        "snmpget": fixture_text("snmpget-timeout.txt"),
        "ldapsearch": fixture_text("ldapsearch-rootdse.txt"),
    }


def test_protocol_audit_pipeline_persists_observations_and_survives_restart(
    durable_settings,
    database,
    job_service,
    evidence_store,
    monkeypatch,
):
    monkeypatch.setattr(
        "protocol_audits.availability.locate_binary",
        _fake_locate(),
    )
    audit = job_service.create_audit(
        profile="standard",
        interface="eth0",
        scope={"observed": ["192.0.2.0/24"]},
    )
    _inventory, confirmed = _seed_inventory(
        database,
        durable_settings,
        evidence_store,
        audit.id,
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="protocol_audit",
        target="eth0",
        parameters={
            "profile": "default",
            "modules": None,
            "confirmed_scope_id": confirmed.id,
        },
        resource_key=f"audit:{audit.id}",
        resource_group="protocol_audit",
        resource_limit=1,
    )
    runner = ProtocolRecordingRunner(_outputs())
    registry = HandlerRegistry()
    registry.register(
        "protocol_audit",
        ProtocolAuditHandler(runner_factory=lambda _context: runner),
    )
    worker = JobWorker(
        worker_id="protocol-integration",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )
    assert worker.run_once() is True
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    stages = {event.stage for event in job_service.list_events(job.id).items}
    assert "loading_inventory" in stages
    assert "matching_services" in stages
    assert "auditing_ssh" in stages
    assert "summarizing" in stages
    status_payload = completed.model_dump(mode="json")
    assert "items" not in status_payload
    result = evidence_store.read_json(
        job_service.artifact(completed.result_reference)
    )
    assert result["schema"] == "protocol-audit-result"
    assert result["summary"]["observations"] >= 6
    store = ProtocolObservationStore(database)
    listing = store.list_observations(audit_id=audit.id, limit=100, offset=0)
    modules = {item.module for item in listing.items}
    assert {"ssh", "http", "tls", "dns"}.issubset(modules)
    ftp_matched = [
        command
        for command in runner.commands
        if "21" in command.args and command.tool not in {"ssh-audit"}
    ]
    assert ftp_matched == []
    tools_used = {
        command.tool
        for command in runner.commands
        if not ProtocolRecordingRunner.VERSION_ARGS.intersection(command.args)
    }
    assert "nmap" not in tools_used

    ssh_only = store.list_observations(
        audit_id=audit.id,
        limit=100,
        offset=0,
        module="ssh",
    )
    assert ssh_only.total == len({item.kind for item in ssh_only.items})

    database.dispose()
    restarted = Database(durable_settings)
    try:
        restarted_jobs = JobService(restarted)
        restarted_evidence = EvidenceStore(restarted, durable_settings)
        restarted_store = ProtocolObservationStore(restarted)
        persisted_job = restarted_jobs.get_job(job.id)
        persisted = restarted_evidence.read_json(
            restarted_jobs.artifact(persisted_job.result_reference)
        )
        observations = restarted_store.list_observations(
            audit_id=audit.id,
            limit=100,
            offset=0,
        )
        assert persisted_job.status == JobStatus.COMPLETED
        assert persisted["summary"]["observations"] == observations.total
        assert observations.total >= 6
        assert any(item.kind == "ssh_algorithms" for item in observations.items)
    finally:
        restarted.dispose()


def test_missing_tool_does_not_fail_the_audit(
    durable_settings,
    database,
    job_service,
    evidence_store,
    monkeypatch,
):
    monkeypatch.setattr(
        "protocol_audits.availability.locate_binary",
        _fake_locate({"ssh-audit"}),
    )
    audit = job_service.create_audit(profile="standard", interface="eth0")
    _seed_inventory(database, durable_settings, evidence_store, audit.id)
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="protocol_audit",
        target="eth0",
        parameters={"profile": "default", "modules": ["ssh", "http"]},
        resource_key=f"audit:{audit.id}",
        resource_group="protocol_audit",
        resource_limit=1,
    )
    runner = ProtocolRecordingRunner(
        {"curl": fixture_text("curl-http.txt")},
        missing={"ssh-audit"},
    )
    registry = HandlerRegistry()
    registry.register(
        "protocol_audit",
        ProtocolAuditHandler(runner_factory=lambda _context: runner),
    )
    worker = JobWorker(
        worker_id="protocol-missing",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )
    worker.run_once()
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    store = ProtocolObservationStore(database)
    kinds = {
        item.kind
        for item in store.list_observations(audit_id=audit.id, limit=50, offset=0).items
    }
    assert "tool_unavailable" in kinds
    assert "http_response" in kinds


def test_protocol_audit_cancellation_is_cancelled_not_failed(
    durable_settings,
    database,
    job_service,
    evidence_store,
    monkeypatch,
):
    monkeypatch.setattr(
        "protocol_audits.availability.locate_binary",
        _fake_locate(),
    )
    audit = job_service.create_audit(profile="standard", interface="eth0")
    _seed_inventory(database, durable_settings, evidence_store, audit.id)
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="protocol_audit",
        target="eth0",
        parameters={"profile": "default", "modules": ["ssh"]},
    )

    class PreCancelledHandler(ProtocolAuditHandler):
        def execute(self, context):
            context.cancellation_token.cancel()
            return super().execute(context)

    registry = HandlerRegistry()
    registry.register(
        "protocol_audit",
        PreCancelledHandler(
            runner_factory=lambda _context: ProtocolRecordingRunner(_outputs())
        ),
    )
    worker = JobWorker(
        worker_id="protocol-cancel",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )
    worker.run_once()
    finished = job_service.get_job(job.id)
    assert finished.status == JobStatus.CANCELLED
    assert finished.status != JobStatus.FAILED
