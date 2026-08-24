import json

import pytest

from engine.interfaces import InterfaceInfo, InterfaceService
from engine.routes import RouteValidationCode, RouteValidationError, RouteResolver
from engine.scope import ActiveProfile, ScopeValidator
from tests.helpers import tool_result


class SequenceRunner:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        if not self.results:
            raise AssertionError(f"Unexpected command: {command.argv}")
        return self.results.pop(0)


class FakeInterfaces(InterfaceService):
    def __init__(self, interface: InterfaceInfo):
        self.interface = interface

    def validate(self, name):
        if name != self.interface.name:
            raise RouteValidationError(
                RouteValidationCode.INTERFACE_MISMATCH,
                f"unknown {name}",
            )
        return self.interface


def ipv4_interface():
    return InterfaceInfo(
        name="eth0",
        state="UP",
        ipv4=["192.0.2.10/24"],
        ipv6=[],
        allowed=True,
    )


def dual_interface():
    return InterfaceInfo(
        name="eth0",
        state="UP",
        ipv4=["192.0.2.10/24"],
        ipv6=["2001:db8::10/64"],
        allowed=True,
    )


def test_route_resolver_accepts_directly_connected_ipv4(durable_settings):
    runner = SequenceRunner(
        [
            tool_result(
                tool="ip",
                stdout=json.dumps(
                    [
                        {
                            "dev": "eth0",
                            "prefsrc": "192.0.2.10",
                            "dst": "192.0.2.0",
                        }
                    ]
                ),
            )
        ]
    )
    scope = ScopeValidator(durable_settings).validate(
        ["192.0.2.0/24"],
        ActiveProfile.STANDARD,
    )
    resolved = RouteResolver(
        runner=runner,
        interfaces=FakeInterfaces(ipv4_interface()),
    ).resolve("eth0", scope)
    assert resolved.routes[0].directly_connected is True
    assert resolved.routes[0].source_address == "192.0.2.10"
    assert resolved.routes[0].representative_address == "192.0.2.1"
    assert runner.commands[-1].args[-1] == "192.0.2.1"


def test_wrong_interface_family_is_rejected(durable_settings):
    scope = ScopeValidator(durable_settings).validate(
        ["2001:db8::10"],
        ActiveProfile.STANDARD,
    )
    with pytest.raises(RouteValidationError) as exc:
        RouteResolver(
            interfaces=FakeInterfaces(ipv4_interface()),
        ).resolve("eth0", scope)
    assert exc.value.code == RouteValidationCode.ADDRESS_FAMILY_UNAVAILABLE


def test_unreachable_scope_and_interface_mismatch(durable_settings):
    scope = ScopeValidator(durable_settings).validate(
        ["198.51.100.10"],
        ActiveProfile.STANDARD,
    )
    missing_route = RouteResolver(
        runner=SequenceRunner(
            [tool_result(tool="ip", success=False, exit_code=1)]
        ),
        interfaces=FakeInterfaces(ipv4_interface()),
    )
    with pytest.raises(RouteValidationError) as missing:
        missing_route.resolve("eth0", scope)
    assert missing.value.code == RouteValidationCode.ROUTE_LOOKUP_FAILED

    mismatch = RouteResolver(
        runner=SequenceRunner(
            [
                tool_result(
                    tool="ip",
                    stdout=json.dumps(
                        [{"dev": "eth1", "prefsrc": "198.51.100.1"}]
                    ),
                )
            ]
        ),
        interfaces=FakeInterfaces(ipv4_interface()),
    )
    with pytest.raises(RouteValidationError) as wrong:
        mismatch.resolve("eth0", scope)
    assert wrong.value.code == RouteValidationCode.INTERFACE_MISMATCH


def test_mixed_scope_keeps_ipv4_when_ipv6_is_unroutable(durable_settings):
    runner = SequenceRunner(
        [
            tool_result(
                tool="ip",
                stdout=json.dumps(
                    [{"dev": "eth0", "prefsrc": "192.0.2.10"}]
                ),
            ),
            tool_result(tool="ip", success=False, exit_code=2),
        ]
    )
    scope = ScopeValidator(durable_settings).validate(
        ["192.0.2.0/24", "2001:db8::10"],
        ActiveProfile.STANDARD,
    )
    resolved = RouteResolver(
        runner=runner,
        interfaces=FakeInterfaces(dual_interface()),
    ).resolve("eth0", scope)
    assert [route.target for route in resolved.routes] == ["192.0.2.0/24"]


def test_local_loopback_route_matches_selected_interface(durable_settings):
    runner = SequenceRunner(
        [
            tool_result(
                tool="ip",
                stdout=json.dumps(
                    [
                        {
                            "type": "local",
                            "dst": "192.0.2.10",
                            "dev": "lo",
                            "prefsrc": "192.0.2.10",
                            "flags": ["local"],
                        }
                    ]
                ),
            )
        ]
    )
    scope = ScopeValidator(durable_settings).validate(
        ["192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    resolved = RouteResolver(
        runner=runner,
        interfaces=FakeInterfaces(ipv4_interface()),
    ).resolve("eth0", scope)
    assert resolved.routes[0].interface == "eth0"
    assert resolved.routes[0].source_address == "192.0.2.10"
