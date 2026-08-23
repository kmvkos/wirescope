import json

import engine.environment as environment


def test_get_interfaces_normalizes_iproute2_output(monkeypatch):
    payload = [
        {
            "ifname": "lo",
            "operstate": "UNKNOWN",
            "address": "00:00:00:00:00:00",
            "mtu": 65536,
            "addr_info": [],
        },
        {
            "ifname": "eth0",
            "operstate": "UP",
            "address": "00:11:22:33:44:55",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
            ],
        },
    ]
    monkeypatch.setattr(
        environment,
        "run_command",
        lambda command: json.dumps(payload) if command == ["ip", "-j", "addr"] else "",
    )
    monkeypatch.setattr(environment, "get_interface_speed", lambda _name: 1000)

    assert environment.get_interfaces() == [
        {
            "name": "eth0",
            "state": "UP",
            "mac": "00:11:22:33:44:55",
            "mtu": 1500,
            "speed_mbps": 1000,
            "ipv4": ["192.0.2.10/24"],
            "ipv6": ["fe80::1/64"],
        }
    ]


def test_get_default_route_returns_none_for_empty_output(monkeypatch):
    monkeypatch.setattr(environment, "run_command", lambda _command: "")

    assert environment.get_default_route() is None
