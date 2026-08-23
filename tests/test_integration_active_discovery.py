from engine.active_profiles import profile_for
from engine.routes import ResolvedScope, TargetRoute
from engine.scope import ActiveProfile, ScopeValidator
from inventory.service import InventoryService
from jobs.handlers.active import ActiveDiscoveryHandler
from jobs.models import JobStatus
from jobs.registry import HandlerRegistry
from jobs.service import JobService
from jobs.worker import JobWorker
from persistence.database import Database
from providers.nmap import NmapProvider
from storage.evidence import EvidenceStore
from tests.fixtures.nmap import fixture_text
from tests.helpers import RecordingRunner, tool_result, xml_writer


class StubResolver:
    def resolve(self, interface_name, scope):
        return ResolvedScope(
            interface=interface_name,
            interface_state="UP",
            vlan_subinterface=False,
            routes=[
                TargetRoute(
                    target=target.value,
                    representative_address=target.value.split("/", 1)[0],
                    family=target.family,
                    interface=interface_name,
                    source_address="192.0.2.1",
                    gateway=None,
                    directly_connected=True,
                )
                for target in scope.targets
            ],
        )


def test_active_discovery_pipeline_survives_restart(
    tmp_path,
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    inventory = InventoryService(database, durable_settings, evidence_store)
    audit = job_service.create_audit(
        profile="standard",
        interface="eth0",
        scope={"observed": ["192.0.2.0/24"]},
    )
    scope = ScopeValidator(durable_settings).validate(
        ["192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    confirmed = inventory.confirm_scope(
        audit_id=audit.id,
        scope=scope,
        interface="eth0",
        route_context={"interface": "eth0"},
        timing_policy=profile_for(
            ActiveProfile.STANDARD,
            durable_settings,
        ).timing,
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="active_discovery",
        target="eth0",
        parameters={
            "interface": "eth0",
            "scope": scope.canonical_targets,
            "profile": "standard",
            "confirmed_scope_id": confirmed.id,
        },
        resource_key="interface:eth0",
        resource_group="active_discovery",
        resource_limit=1,
    )

    xml_map = {
        "host": fixture_text("linux_host.xml"),
        "tcp": fixture_text("linux_host.xml"),
        "udp": fixture_text("empty_valid.xml"),
    }

    def factory(command):
        if "--version" in command.args:
            return tool_result(
                tool="nmap",
                stdout="Nmap version 7.95 ( https://nmap.org )\n",
            )
        if "-sn" in command.args:
            xml = xml_map["host"]
        elif "-sU" in command.args:
            xml = xml_map["udp"]
        else:
            xml = xml_map["tcp"]
        return xml_writer(xml, tmp_path)(command)

    nmap = NmapProvider(
        runner=RecordingRunner(factory),
        settings=durable_settings,
        privileged=True,
    )
    registry = HandlerRegistry()
    registry.register(
        "active_discovery",
        ActiveDiscoveryHandler(
            nmap_factory=lambda _context: nmap,
            route_resolver_factory=lambda _context: StubResolver(),
        ),
    )
    worker = JobWorker(
        worker_id="active-integration",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )

    assert worker.run_once() is True
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    assert completed.result_available
    stages = {event.stage for event in job_service.list_events(job.id).items}
    assert "validating_scope" in stages
    assert "discovering_hosts" in stages
    assert "persisting_inventory" in stages
    status_payload = completed.model_dump(mode="json")
    assert "items" not in status_payload
    result = evidence_store.read_json(
        job_service.artifact(completed.result_reference)
    )
    assert result["schema"] == "active-discovery-result"
    assert "hosts" not in result
    assert result["summary"]["assets"] == 1
    assert result["summary"]["services"] == 2

    listing = inventory.list_assets(audit_id=audit.id, limit=10, offset=0)
    assert listing.total == 1
    assert listing.items[0].mac == "00:11:22:33:44:55"

    database.dispose()
    restarted = Database(durable_settings)
    try:
        restarted_jobs = JobService(restarted)
        restarted_evidence = EvidenceStore(restarted, durable_settings)
        restarted_inventory = InventoryService(
            restarted,
            durable_settings,
            restarted_evidence,
        )
        persisted_job = restarted_jobs.get_job(job.id)
        persisted = restarted_evidence.read_json(
            restarted_jobs.artifact(persisted_job.result_reference)
        )
        assets = restarted_inventory.list_assets(
            audit_id=audit.id,
            limit=10,
            offset=0,
        )
        services = restarted_inventory.list_services(
            audit_id=audit.id,
            limit=20,
            offset=0,
        )
        assert persisted_job.status == JobStatus.COMPLETED
        assert persisted["summary"]["assets"] == 1
        assert assets.total == 1
        assert services.total == 2
        assert assets.items[0].os_name == "Linux 5.15"
        assert assets.items[0].os_accuracy == 95
    finally:
        restarted.dispose()
