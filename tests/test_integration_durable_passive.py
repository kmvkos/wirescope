from engine.passive import PassivePipeline
from inventory.service import InventoryService
from jobs.handlers.passive import PassiveDiscoveryHandler
from jobs.models import JobStatus, RetentionClass
from jobs.registry import HandlerRegistry
from jobs.service import JobService
from jobs.worker import JobWorker
from persistence.database import Database
from storage.evidence import EvidenceStore
from tests.fixtures.packets import write_passive_fixture


class FixturePassivePipeline(PassivePipeline):
    def __init__(self, pcap):
        super().__init__()
        self.pcap = pcap

    def run(
        self,
        interface_name,
        duration_seconds=None,
        *,
        retain_capture=False,
        cancellation_token=None,
        progress_callback=None,
    ):
        for percentage, stage, message in (
            (5, "preparing_interface", "Preparing fixture interface"),
            (10, "capturing", "Using fixture capture"),
            (50, "capture_complete", "Fixture capture ready"),
            (60, "parsing_packets", "Parsing fixture packets"),
            (85, "running_sensors", "Running passive sensors"),
            (95, "building_assessment", "Building assessment"),
        ):
            if progress_callback:
                progress_callback(percentage, stage, message)
        return self.analyze_pcap(
            self.pcap,
            interface_name=interface_name,
            cancellation_token=cancellation_token,
        )


def test_passive_job_result_survives_application_object_restart(
    tmp_path,
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    pcap = write_passive_fixture(tmp_path / "passive.pcap")
    audit = job_service.create_audit(
        profile="passive",
        interface="fixture0",
        scope={"mode": "fixture"},
    )
    environment = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="environment_snapshot",
        document={
            "schema": "environment-snapshot",
            "schema_version": 1,
            "environment": {"hostname": "fixture"},
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="environment-snapshot",
        schema_version=1,
    )
    job_service.set_environment_reference(audit.id, environment.id)
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="passive_discovery",
        target="fixture0",
        parameters={
            "interface": "fixture0",
            "duration_seconds": 5,
        },
        resource_key="interface:fixture0",
        resource_group="packet_capture",
        resource_limit=1,
    )
    registry = HandlerRegistry()
    registry.register(
        "passive_discovery",
        PassiveDiscoveryHandler(
            pipeline_factory=lambda: FixturePassivePipeline(pcap)
        ),
    )
    active_worker = JobWorker(
        worker_id="integration-worker",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )

    assert active_worker.run_once() is True
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    assert completed.result_available
    assert any(
        event.stage == "parsing_packets"
        for event in job_service.list_events(job.id).items
    )

    database.dispose()
    restarted_database = Database(durable_settings)
    try:
        restarted_service = JobService(restarted_database)
        restarted_evidence = EvidenceStore(
            restarted_database,
            durable_settings,
        )
        persisted_job = restarted_service.get_job(job.id)
        persisted_audit = restarted_service.get_audit(audit.id)
        result_artifact = restarted_service.artifact(
            persisted_job.result_reference
        )
        result = restarted_evidence.read_json(result_artifact)

        assert persisted_job.status == JobStatus.COMPLETED
        assert persisted_audit.environment_snapshot_reference == environment.id
        assert result["schema"] == "passive-result"
        assert result["schema_version"] == 1
        assert result["result"]["sensors"]["lldp"]["detected"] is True
        assert result["result"]["metrics"]["decode_subprocesses"] == 1
        inventory = InventoryService(
            restarted_database,
            durable_settings,
            restarted_evidence,
        )
        assert inventory.summary(audit.id).assets >= 1
    finally:
        restarted_database.dispose()
