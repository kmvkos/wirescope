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


def test_get_default_routes_keeps_nonpreferred_route_for_second_interface(monkeypatch):
    payload = [
        {"dst": "default", "gateway": "192.168.32.2", "dev": "ens38", "metric": 100},
        {"dst": "default", "gateway": "10.11.11.11", "dev": "ens37", "metric": 600},
    ]
    monkeypatch.setattr(
        environment,
        "run_command",
        lambda command: json.dumps(payload)
        if command == ["ip", "-j", "-4", "route", "show", "default"]
        else "",
    )

    assert environment.get_default_routes() == [
        {
            "gateway": "192.168.32.2",
            "interface": "ens38",
            "source_address": None,
            "metric": 100,
            "protocol": None,
        },
        {
            "gateway": "10.11.11.11",
            "interface": "ens37",
            "source_address": None,
            "metric": 600,
            "protocol": None,
        },
    ]


def test_systemd_dhcp_lease_is_bound_to_ifindex(tmp_path):
    sys_class = tmp_path / "sys" / "class" / "net"
    lease_dir = tmp_path / "run" / "systemd" / "netif" / "leases"
    (sys_class / "ens37").mkdir(parents=True)
    (sys_class / "ens37" / "ifindex").write_text("2\n")
    lease_dir.mkdir(parents=True)
    (lease_dir / "2").write_text(
        "ADDRESS=10.11.11.124\n"
        "ROUTER=10.11.11.11\n"
        "DNS=10.11.11.11 1.1.1.1\n"
        "SERVER_ADDRESS=10.11.11.11\n"
    )

    assert environment.get_systemd_dhcp_leases(lease_dir, sys_class) == [
        {
            "interface": "ens37",
            "address": "10.11.11.124",
            "routers": ["10.11.11.11"],
            "dns": ["10.11.11.11", "1.1.1.1"],
            "server_address": "10.11.11.11",
            "source": "systemd-networkd-lease",
        }
    ]
