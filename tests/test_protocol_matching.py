from engine.scope import ActiveProfile
from inventory.models import ConfirmedScopeRecord
from protocol_audits.matching import match_work, matching_modules
from protocol_audits.modules.gated import NucleiModule, TestsslModule
from protocol_audits.registry import default_registry
from protocol_audits.targets import address_in_scope, build_probe_target
from tests.helpers import sample_asset, sample_service, utcnow


def _scope():
    now = utcnow()
    return ConfirmedScopeRecord(
        id="scope-1",
        audit_id="audit-1",
        created_at=now,
        activated_at=now,
        profile=ActiveProfile.STANDARD,
        interface="eth0",
        targets=["192.0.2.0/24"],
        address_families=[4],
        address_count=256,
        route_context={},
        timing_policy="T3",
        actor=None,
        snapshot_hash="abc",
    )


def test_orchestrator_only_dispatches_matching_open_services():
    registry = default_registry()
    ssh = sample_service(port=22, name="ssh", service_id="ssh")
    http = sample_service(port=80, name="http", product="nginx", service_id="http")
    ftp = sample_service(port=21, name="ftp", product="vsftpd", service_id="ftp")
    filtered = sample_service(
        port=22,
        name="ssh",
        state="filtered",
        service_id="filtered",
    )
    asset = sample_asset()
    work = match_work(
        registry=registry,
        assets=[asset],
        services=[ssh, http, ftp, filtered],
        scope=_scope(),
    )
    modules = {item.module for item in work}
    assert modules == {"ssh", "http"}
    assert matching_modules(registry, ftp) == []


def test_https_matches_tls_and_http_but_not_ssh():
    registry = default_registry()
    https = sample_service(
        port=443,
        name="https",
        product="nginx",
        tunnel="ssl",
        service_id="https",
    )
    names = {module.name for module in matching_modules(registry, https)}
    assert names == {"tls", "http"}


def test_out_of_scope_address_is_not_probed():
    asset = sample_asset(address="198.51.100.10")
    service = sample_service(port=22, name="ssh")
    assert build_probe_target(asset, service, _scope()) is None
    assert address_in_scope("192.0.2.10", _scope()) is True
    assert address_in_scope("198.51.100.10", _scope()) is False


def test_gated_modules_are_never_in_default_dispatch():
    registry = default_registry()
    assert "nuclei" not in registry.default_names
    assert "nikto" not in registry.default_names
    assert "testssl" not in registry.default_names
    assert registry.is_gated("nuclei")
    https = sample_service(port=443, name="https")
    assert NucleiModule().matches(https) is False
    assert TestsslModule().availability(None, None).available is False
