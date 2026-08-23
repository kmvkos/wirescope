from engine.active_profiles import profile_for
from engine.routes import ResolvedScope, TargetRoute
from engine.scope import ActiveProfile, ScopeValidator
from jobs.errors import JobCancelled, JobExecutionError
from providers.nmap import NmapProvider
from providers.tools import CancellationToken, ToolError, ToolErrorCode
from tests.helpers import RecordingRunner, tool_result, xml_writer
from tests.fixtures.nmap import fixture_text


def scope_and_route(settings, targets, profile=ActiveProfile.STANDARD):
    validated = ScopeValidator(settings).validate(targets, profile)
    family = validated.address_families[0]
    resolved = ResolvedScope(
        interface="eth0",
        interface_state="UP",
        vlan_subinterface=False,
        routes=[
            TargetRoute(
                target=item.value,
                representative_address=item.value.split("/", 1)[0],
                family=item.family,
                interface="eth0",
                source_address=(
                    "192.0.2.10" if item.family == 4 else "2001:db8::10"
                ),
                gateway=None if family == 4 else "fe80::1",
                directly_connected=item.family == 4,
            )
            for item in validated.targets
        ],
    )
    return validated, resolved


def test_command_builder_profiles_ipv4_and_ipv6(durable_settings, tmp_path):
    xml = tmp_path / "scan.xml"
    targets = tmp_path / "targets.txt"
    for profile_name, privileged, expect in (
        (ActiveProfile.DISCOVERY, True, ("-sn", "-PR", "-T3")),
        (ActiveProfile.STANDARD, True, ("-sS", "--top-ports", "1000", "-sV")),
        (ActiveProfile.DEEP, True, ("-sS", "1-65535", "-sV", "-O")),
        (ActiveProfile.STANDARD, False, ("-sT", "--unprivileged")),
    ):
        provider = NmapProvider(
            runner=RecordingRunner(),
            settings=durable_settings,
            privileged=privileged,
        )
        scope, resolved = scope_and_route(
            durable_settings,
            ["192.0.2.0/24"],
            profile_name,
        )
        profile = profile_for(profile_name, durable_settings)
        if profile_name == ActiveProfile.DISCOVERY:
            plan = provider.build_host_discovery(
                scope=scope,
                resolved=resolved,
                profile=profile,
                xml_path=xml,
                target_file=targets,
            )
        else:
            plan = provider.build_tcp_scan(
                scope=scope,
                resolved=resolved,
                profile=profile,
                xml_path=xml,
                target_file=targets,
            )
        joined = " ".join(plan.args)
        for token in expect:
            assert token in joined
        assert "-T5" not in joined
        assert "-sC" not in joined
        assert "--script" not in joined
        assert plan.timing == "T3"
        assert plan.args[-4:] == ["-e", "eth0", "-oX", str(xml)] or "-e" in plan.args

    provider = NmapProvider(privileged=True, settings=durable_settings)
    scope, resolved = scope_and_route(
        durable_settings,
        ["2001:db8::10"],
        ActiveProfile.DISCOVERY,
    )
    plan = provider.build_host_discovery(
        scope=scope,
        resolved=resolved,
        profile=profile_for(ActiveProfile.DISCOVERY, durable_settings),
        xml_path=xml,
        target_file=targets,
    )
    assert "-6" in plan.args
    assert plan.host_discovery_method == "ipv6-neighbor-discovery"


def test_udp_and_os_fallback(durable_settings, tmp_path):
    xml = tmp_path / "scan.xml"
    targets = tmp_path / "targets.txt"
    scope, resolved = scope_and_route(durable_settings, ["192.0.2.10"])
    privileged = NmapProvider(privileged=True, settings=durable_settings)
    unprivileged = NmapProvider(privileged=False, settings=durable_settings)
    profile = profile_for(ActiveProfile.STANDARD, durable_settings)
    udp = privileged.build_udp_scan(
        scope=scope,
        resolved=resolved,
        profile=profile,
        xml_path=xml,
        target_file=targets,
    )
    skipped = unprivileged.build_udp_scan(
        scope=scope,
        resolved=resolved,
        profile=profile,
        xml_path=xml,
        target_file=targets,
    )
    tcp = unprivileged.build_tcp_scan(
        scope=scope,
        resolved=resolved,
        profile=profile,
        xml_path=xml,
        target_file=targets,
    )
    assert udp is not None and "-sU" in udp.args
    assert "53" in udp.udp_ports
    assert skipped is not None and skipped.args == []
    assert "udp-skipped-unprivileged" in skipped.fallbacks
    assert tcp.tcp_method == "connect"
    assert tcp.os_detection is False
    assert "os-detection-skipped-unprivileged" in tcp.fallbacks


def test_nmap_run_parses_xml_and_supports_cancel_timeout(
    durable_settings,
    tmp_path,
    evidence_store,
    job_service,
):
    xml = fixture_text("empty_valid.xml")
    provider = NmapProvider(
        runner=RecordingRunner(xml_writer(xml, tmp_path)),
        settings=durable_settings,
        privileged=True,
    )
    scope, resolved = scope_and_route(durable_settings, ["192.0.2.10"])
    plan = provider.build_host_discovery(
        scope=scope,
        resolved=resolved,
        profile=profile_for(ActiveProfile.DISCOVERY, durable_settings),
        xml_path=tmp_path / "out.xml",
        target_file=provider.write_target_file(
            ["192.0.2.10"],
            tmp_path,
        ),
    )
    audit = job_service.create_audit(profile="standard", interface="eth0")
    run = provider.run_plan(
        plan,
        timeout_seconds=30,
        evidence_store=evidence_store,
        audit_id=audit.id,
    )
    assert run.document is not None
    assert run.document.hosts == []
    assert run.xml_artifact_id is not None
    assert (tmp_path / "out.xml").exists() is False

    cancelling = NmapProvider(
        runner=RecordingRunner(),
        settings=durable_settings,
        privileged=True,
    )
    token = CancellationToken()
    token.cancel()
    try:
        cancelling.run_plan(plan, timeout_seconds=30, cancellation_token=token)
        raise AssertionError("expected cancellation")
    except JobCancelled:
        pass

    def timeout_factory(command):
        return tool_result(
            tool="nmap",
            success=False,
            exit_code=None,
        ).model_copy(
            update={
                "timed_out": True,
                "error": ToolError(
                    code=ToolErrorCode.TIMEOUT,
                    message="timed out",
                    retryable=True,
                ),
            }
        )

    timed = NmapProvider(
        runner=RecordingRunner(timeout_factory),
        settings=durable_settings,
        privileged=True,
    )
    try:
        timed.run_plan(plan, timeout_seconds=1)
        raise AssertionError("expected timeout")
    except JobExecutionError as exc:
        assert exc.error.category.value == "timeout"
