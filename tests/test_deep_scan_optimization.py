from engine.active_profiles import profile_for
from engine.routes import ResolvedScope, TargetRoute
from engine.scope import ActiveProfile, ScopeValidator
from parsers.nmap import parse_nmap_xml
from providers.nmap import NmapProvider
from tests.fixtures.nmap import fixture_text
from tests.helpers import RecordingRunner


def _scope_and_route(settings, *, direct: bool = True):
    scope = ScopeValidator(settings).validate(
        ["192.0.2.10"],
        ActiveProfile.DEEP,
    )
    resolved = ResolvedScope(
        interface="eth0",
        interface_state="UP",
        vlan_subinterface=False,
        routes=[
            TargetRoute(
                target="192.0.2.10/32",
                representative_address="192.0.2.10",
                family=4,
                interface="eth0",
                source_address="192.0.2.1",
                gateway=None if direct else "192.0.2.254",
                directly_connected=direct,
            )
        ],
    )
    return scope, resolved


def test_deep_full_range_sweep_is_fast_pass_without_service_or_os_probes(
    durable_settings,
    tmp_path,
):
    provider = NmapProvider(
        runner=RecordingRunner(),
        settings=durable_settings,
        privileged=True,
    )
    scope, resolved = _scope_and_route(durable_settings, direct=True)
    profile = profile_for(ActiveProfile.DEEP, durable_settings)

    plan = provider.build_tcp_sweep(
        scope=scope,
        resolved=resolved,
        profile=profile,
        xml_path=tmp_path / "sweep.xml",
        target_file=tmp_path / "targets.txt",
    )

    assert plan.scan_kind == "tcp_sweep"
    assert plan.tcp_ports == "1-65535"
    assert "-p" in plan.args and "1-65535" in plan.args
    assert "-sS" in plan.args
    assert "-sV" not in plan.args
    assert "-O" not in plan.args
    assert "--open" in plan.args
    assert "--stats-every" in plan.args and "5s" in plan.args
    assert "-v" in plan.args
    assert plan.timing == "T4"
    retry_index = plan.args.index("--max-retries")
    assert plan.args[retry_index + 1] == "1"


def test_deep_routed_sweep_keeps_conservative_t3(durable_settings, tmp_path):
    provider = NmapProvider(
        runner=RecordingRunner(),
        settings=durable_settings,
        privileged=True,
    )
    scope, resolved = _scope_and_route(durable_settings, direct=False)
    plan = provider.build_tcp_sweep(
        scope=scope,
        resolved=resolved,
        profile=profile_for(ActiveProfile.DEEP, durable_settings),
        xml_path=tmp_path / "sweep.xml",
        target_file=tmp_path / "targets.txt",
    )

    assert plan.timing == "T3"
    assert "-T3" in plan.args
    retry_index = plan.args.index("--max-retries")
    assert plan.args[retry_index + 1] == "2"


def test_deep_fingerprint_only_uses_ports_found_by_sweep(durable_settings, tmp_path):
    provider = NmapProvider(
        runner=RecordingRunner(),
        settings=durable_settings,
        privileged=True,
    )
    document = parse_nmap_xml(fixture_text("linux_host.xml"))
    open_ports = provider.open_tcp_ports(document)
    targets = provider.targets_with_open_tcp(document)

    assert open_ports
    assert targets == ["192.0.2.10"]

    scope, resolved = _scope_and_route(durable_settings, direct=True)
    plan = provider.build_tcp_fingerprint(
        scope=scope,
        resolved=resolved,
        profile=profile_for(ActiveProfile.DEEP, durable_settings),
        ports=open_ports,
        xml_path=tmp_path / "fingerprint.xml",
        target_file=tmp_path / "targets.txt",
    )

    assert plan is not None
    assert plan.scan_kind == "tcp_fingerprint"
    assert plan.tcp_ports == ",".join(str(port) for port in open_ports)
    assert "1-65535" not in plan.args
    assert "-sV" in plan.args
    assert "--version-intensity" in plan.args
    assert "7" in plan.args
    assert "-O" in plan.args
    assert plan.timing == "T4"
