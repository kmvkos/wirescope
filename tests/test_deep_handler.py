from engine.active_profiles import profile_for
from engine.routes import ResolvedScope, TargetRoute
from engine.scope import ActiveProfile, ScopeValidator
from inventory.service import InventoryService
from jobs.handlers.active import ActiveDiscoveryHandler
from jobs.models import JobStatus
from jobs.registry import HandlerRegistry
from jobs.worker import JobWorker
from providers.nmap import NmapProvider
from tests.fixtures.nmap import fixture_text
from tests.helpers import RecordingRunner, tool_result, xml_writer


class _DirectResolver:
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


def test_deep_handler_runs_full_sweep_then_fingerprints_only_open_ports(
    tmp_path,
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    inventory = InventoryService(database, durable_settings, evidence_store)
    audit = job_service.create_audit(
        profile="deep",
        interface="eth0",
        scope={"observed": ["192.0.2.10/32"]},
    )
    scope = ScopeValidator(durable_settings).validate(
        ["192.0.2.10"],
        ActiveProfile.DEEP,
    )
    confirmed = inventory.confirm_scope(
        audit_id=audit.id,
        scope=scope,
        interface="eth0",
        route_context={"interface": "eth0"},
        timing_policy=profile_for(ActiveProfile.DEEP, durable_settings).timing,
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="active_discovery",
        target="eth0",
        parameters={
            "interface": "eth0",
            "scope": scope.canonical_targets,
            "profile": "deep",
            "confirmed_scope_id": confirmed.id,
        },
        resource_key="interface:eth0",
        resource_group="active_discovery",
        resource_limit=1,
    )

    host_xml = fixture_text("linux_host.xml")
    empty_xml = fixture_text("empty_valid.xml")

    def factory(command):
        if "--version" in command.args:
            return tool_result(
                tool="nmap",
                stdout="Nmap version 7.95 ( https://nmap.org )\n",
            )
        if "-sU" in command.args:
            xml = empty_xml
        else:
            xml = host_xml
        return xml_writer(xml, tmp_path)(command)

    runner = RecordingRunner(factory)
    nmap = NmapProvider(
        runner=runner,
        settings=durable_settings,
        privileged=True,
    )
    registry = HandlerRegistry()
    registry.register(
        "active_discovery",
        ActiveDiscoveryHandler(
            nmap_factory=lambda _context: nmap,
            route_resolver_factory=lambda _context: _DirectResolver(),
        ),
    )
    worker = JobWorker(
        worker_id="deep-integration",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )

    assert worker.run_once() is True
    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    result = evidence_store.read_json(job_service.artifact(completed.result_reference))

    nmap_commands = [command.args for command in runner.commands if "--version" not in command.args]
    sweep = next(args for args in nmap_commands if "1-65535" in args)
    fingerprint = next(args for args in nmap_commands if "-sV" in args and "-sU" not in args)

    assert "-sV" not in sweep
    assert "-O" not in sweep
    assert "-T4" in sweep
    assert "--max-retries" in sweep
    assert sweep[sweep.index("--max-retries") + 1] == "1"

    assert "1-65535" not in fingerprint
    assert fingerprint[fingerprint.index("-p") + 1] == "22,80"
    assert "-sV" in fingerprint
    assert "-O" in fingerprint

    methods = result["scan_methods"]
    assert methods["tcp_strategy"] == "full-sweep-then-fingerprint"
    assert methods["tcp_open_ports_discovered"] == 2
    assert methods["tcp_fingerprint_ports"] == "22,80"
    assert methods["effective_tcp_timing"] == "T4"
    assert [run["scan_kind"] for run in result["runs"]] == [
        "host_discovery",
        "tcp_sweep",
        "tcp_fingerprint",
        "udp_scan",
    ]
