import json
from dataclasses import replace
from pathlib import Path

from appliance.netctl import (
    ApplySpec,
    CmdResult,
    NetctlError,
    apply_configuration,
    collect_inventory,
    evaluate_safety,
    gui_urls,
    validate_spec,
)
from engine.network import NetworkService
from tests.helpers import http_request
from tests.test_api import create_audit


def _ok(stdout=""):
    return CmdResult(argv=("ok",), returncode=0, stdout=stdout)


def _addr_payload():
    return [
        {
            "ifname": "lo",
            "operstate": "UNKNOWN",
            "link_type": "loopback",
            "flags": ["LOOPBACK", "UP"],
            "address": "00:00:00:00:00:00",
            "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
            ],
        },
        {
            "ifname": "eth0",
            "operstate": "UP",
            "link_type": "ether",
            "flags": ["BROADCAST", "UP"],
            "address": "02:00:00:00:00:10",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "192.0.2.10",
                    "prefixlen": 24,
                    "dynamic": True,
                }
            ],
        },
        {
            "ifname": "eth1",
            "operstate": "DOWN",
            "link_type": "ether",
            "flags": ["BROADCAST"],
            "address": "02:00:00:00:00:11",
            "addr_info": [],
        },
    ]


def _route_payload():
    return [
        {
            "dst": "default",
            "gateway": "192.0.2.1",
            "dev": "eth0",
            "protocol": "dhcp",
        },
        {"dst": "192.0.2.0/24", "dev": "eth0", "protocol": "kernel"},
    ]


class ScriptedRunner:
    def __init__(self):
        self.commands = []

    def __call__(self, argv):
        self.commands.append(tuple(argv))
        name = Path(argv[0]).name
        if name == "ip" and "-j" in argv and "addr" in argv:
            return _ok(json.dumps(_addr_payload()))
        if name == "ip" and "-j" in argv and "route" in argv and "get" in argv:
            return _ok(json.dumps([{"dev": "eth0", "prefsrc": "192.0.2.10"}]))
        if name == "ip" and "-j" in argv and "route" in argv:
            return _ok(json.dumps(_route_payload()))
        if name == "nmcli" and "general" in argv:
            return _ok("running\n")
        if name == "nmcli" and "connection" in argv and "show" in argv:
            return _ok("wirescope-eth0:eth0\nwirescope-eth1:eth1\n")
        if name == "nmcli":
            return _ok("")
        if name == "ip":
            return _ok("")
        return CmdResult(tuple(argv), 1, "", "unexpected")


def _which(name):
    if name in {"nmcli", "ip", "sudo"}:
        return f"/usr/bin/{name}"
    return None


def test_gui_urls_list_up_ipv4_when_lan_bound():
    inventory = collect_inventory(ScriptedRunner(), which=_which)
    urls = gui_urls(
        bind_host="0.0.0.0",
        bind_port=8000,
        interfaces=inventory.interfaces,
    )
    assert "http://192.0.2.10:8000/" in urls
    assert "http://127.0.0.1:8000/" in urls


def test_capture_apply_uses_nmcli_never_default(tmp_path):
    runner = ScriptedRunner()
    result = apply_configuration(
        ApplySpec(
            interface="eth1",
            role="capture",
            method="none",
            bind_host="0.0.0.0",
        ),
        runner,
        which=_which,
        roles_path=tmp_path / "roles.json",
    )
    joined = [" ".join(item) for item in runner.commands]
    assert any("never-default yes" in item for item in joined)
    assert any(item[:4] == ("/usr/bin/nmcli", "connection", "modify", "wirescope-eth1") for item in runner.commands)
    assert "capture_no_default_route" in result.warnings
    assert (tmp_path / "roles.json").read_text(encoding="utf-8").find("eth1") >= 0


def test_management_dhcp_keeps_default_route_flag(tmp_path):
    runner = ScriptedRunner()
    apply_configuration(
        ApplySpec(interface="eth0", role="management", method="dhcp", bind_host="0.0.0.0"),
        runner,
        which=_which,
        roles_path=tmp_path / "roles.json",
    )
    joined = "\n".join(" ".join(item) for item in runner.commands)
    assert "ipv4.never-default no" in joined


def test_refuse_last_lan_ipv4_without_confirm(tmp_path):
    runner = ScriptedRunner()
    inventory = collect_inventory(runner, which=_which, roles_path=tmp_path / "roles.json")
    spec = ApplySpec(
        interface="eth0",
        role="capture",
        method="none",
        bind_host="0.0.0.0",
    )
    decision = evaluate_safety(inventory, spec)
    assert decision.needs_confirm is True
    assert "last_lan_ipv4" in decision.reasons
    try:
        apply_configuration(spec, runner, which=_which, roles_path=tmp_path / "roles.json")
        raise AssertionError("expected confirm_required")
    except NetctlError as exc:
        assert exc.code == "confirm_required"


def test_validate_management_rejects_no_address():
    try:
        validate_spec(ApplySpec(interface="eth0", role="management", method="none"))
        raise AssertionError("expected management_needs_address")
    except NetctlError as exc:
        assert exc.code == "management_needs_address"


def test_network_api_viewer_forbidden(api_context):
    app, _service, _evidence, _environment = api_context
    listing = http_request(app, "GET", "/api/network/interfaces", as_role="viewer")
    apply = http_request(
        app,
        "POST",
        "/api/network/interfaces/eth0",
        as_role="viewer",
        json={"role": "capture", "method": "none"},
    )
    assert listing.status_code == 403
    assert apply.status_code == 403


def test_network_api_apply_with_mocked_helper(api_context, tmp_path):
    from backend.app import create_app

    app, job_service, evidence, _environment = api_context
    runner = ScriptedRunner()
    network = NetworkService(
        replace(app.state.settings, bind_host="0.0.0.0"),
        runner=runner,
        which=_which,
        use_sudo=False,
        roles_path=tmp_path / "roles.json",
    )
    wired = create_app(
        settings=replace(app.state.settings, bind_host="0.0.0.0"),
        database=app.state.database,
        job_service=job_service,
        evidence_store=evidence,
        network_service=network,
    )
    wired.state.auth_cookies = app.state.auth_cookies
    listing = http_request(wired, "GET", "/api/network/interfaces")
    assert listing.status_code == 200
    names = [item["name"] for item in listing.json()["interfaces"]]
    assert "eth0" in names
    assert "eth1" in names
    applied = http_request(
        wired,
        "POST",
        "/api/network/interfaces/eth1",
        json={"role": "capture", "method": "none"},
    )
    assert applied.status_code == 200
    assert any("never-default yes" in " ".join(item) for item in runner.commands)
    assert "http://192.0.2.10:8000/" in applied.json()["gui_urls"]


def test_network_api_confirm_conflict(api_context, tmp_path):
    from backend.app import create_app

    app, service, evidence, _environment = api_context
    runner = ScriptedRunner()
    network = NetworkService(
        replace(app.state.settings, bind_host="0.0.0.0"),
        runner=runner,
        which=_which,
        use_sudo=False,
        roles_path=tmp_path / "roles.json",
    )
    wired = create_app(
        settings=replace(app.state.settings, bind_host="0.0.0.0"),
        database=app.state.database,
        job_service=service,
        evidence_store=evidence,
        network_service=network,
    )
    wired.state.auth_cookies = app.state.auth_cookies
    denied = http_request(
        wired,
        "POST",
        "/api/network/interfaces/eth0",
        json={"role": "capture", "method": "none"},
    )
    assert denied.status_code == 409
    assert denied.json()["detail"]["code"] == "confirm_required"
    confirmed = http_request(
        wired,
        "POST",
        "/api/network/interfaces/eth0",
        json={"role": "capture", "method": "none", "confirm": True},
    )
    assert confirmed.status_code == 200


def test_create_audit_still_works_alongside_network_screen(api_context):
    created = create_audit(api_context[0])
    assert created.status_code == 201
