from dataclasses import replace
import json

import pytest

from config.settings import get_settings
from engine.interfaces import (
    InterfaceService,
    InterfaceValidationCode,
    InterfaceValidationError,
)
from providers.tools import ToolError, ToolErrorCode
from tests.helpers import tool_result


class FakeRunner:
    def __init__(self, result):
        self.result = result
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        return self.result


def interface_payload():
    return [
        {
            "ifname": "lo",
            "operstate": "UNKNOWN",
            "link_type": "loopback",
            "flags": ["LOOPBACK", "UP"],
            "address": "00:00:00:00:00:00",
            "mtu": 65536,
            "addr_info": [],
        },
        {
            "ifname": "eth0",
            "operstate": "UP",
            "link_type": "ether",
            "flags": ["BROADCAST", "UP"],
            "address": "02:00:00:00:00:10",
            "mtu": 1500,
            "addr_info": [
                {
                    "family": "inet",
                    "local": "192.0.2.10",
                    "prefixlen": 24,
                }
            ],
        },
        {
            "ifname": "eth1",
            "operstate": "DOWN",
            "link_type": "ether",
            "flags": ["BROADCAST"],
            "address": "02:00:00:00:00:11",
            "mtu": 1500,
            "addr_info": [],
        },
    ]


def service(tmp_path, *, allowed=()):
    settings = replace(
        get_settings(),
        allowed_interfaces=allowed,
    )
    runner = FakeRunner(
        tool_result(tool="ip", stdout=json.dumps(interface_payload()))
    )
    return InterfaceService(
        runner=runner,
        settings=settings,
        sys_class_net=tmp_path,
    )


def test_interface_validator_accepts_discovered_up_interface(tmp_path):
    interface = service(tmp_path).validate("eth0")

    assert interface.name == "eth0"
    assert interface.allowed is True
    assert interface.ipv4 == ["192.0.2.10/24"]


@pytest.mark.parametrize(
    ("name", "expected_code"),
    [
        ("missing0", InterfaceValidationCode.UNKNOWN_INTERFACE),
        ("lo", InterfaceValidationCode.LOOPBACK_DENIED),
        ("eth1", InterfaceValidationCode.LINK_NOT_UP),
    ],
)
def test_interface_validator_rejects_unsafe_interfaces(
    tmp_path,
    name,
    expected_code,
):
    with pytest.raises(InterfaceValidationError) as exc_info:
        service(tmp_path).validate(name)

    assert exc_info.value.code == expected_code


def test_down_interface_is_selectable_for_capture_picker(tmp_path):
    discovered = service(tmp_path).discover()
    by_name = {item.name: item for item in discovered.interfaces}
    assert by_name["eth1"].selectable is True
    assert by_name["eth1"].allowed is False
    assert by_name["eth1"].role_hint == "capture"
    assert by_name["eth0"].selectable is True
    assert by_name["lo"].selectable is False


def test_interface_allowlist_is_enforced(tmp_path):
    with pytest.raises(InterfaceValidationError) as exc_info:
        service(tmp_path, allowed=("eth1",)).validate("eth0")

    assert exc_info.value.code == InterfaceValidationCode.NOT_ALLOWED


def test_interface_discovery_rejects_malformed_json(tmp_path):
    runner = FakeRunner(tool_result(tool="ip", stdout="{bad json"))
    interface_service = InterfaceService(
        runner=runner,
        settings=get_settings(),
        sys_class_net=tmp_path,
    )

    with pytest.raises(InterfaceValidationError) as exc_info:
        interface_service.discover()

    assert (
        exc_info.value.code
        == InterfaceValidationCode.INVALID_DISCOVERY_DATA
    )


def test_interface_discovery_preserves_tool_failure(tmp_path):
    runner = FakeRunner(
        tool_result(
            tool="ip",
            exit_code=None,
            success=False,
            error=ToolError(
                code=ToolErrorCode.MISSING_BINARY,
                message="ip missing",
            ),
        )
    )
    interface_service = InterfaceService(
        runner=runner,
        settings=get_settings(),
        sys_class_net=tmp_path,
    )

    with pytest.raises(InterfaceValidationError) as exc_info:
        interface_service.discover()

    assert exc_info.value.code == InterfaceValidationCode.DISCOVERY_FAILED
    assert "ip missing" in exc_info.value.message
