from topology.interface_gateway import _candidate_gateways


def test_gateway_candidates_ignore_host_preferred_route_on_other_nic():
    environment = {
        "default_route": {"gateway": "192.168.32.2", "interface": "ens38"},
        "default_routes": [
            {"gateway": "192.168.32.2", "interface": "ens38", "metric": 100},
            {"gateway": "10.11.11.11", "interface": "ens37", "metric": 600},
        ],
        "dhcp_leases": [],
    }

    candidates = _candidate_gateways(environment, "ens37")

    assert candidates == [
        {
            "address": "10.11.11.11",
            "provenance": "interface-default-route",
            "source": "local route table",
        }
    ]


def test_dhcp_router_option_recovers_gateway_when_interface_has_no_default_route():
    environment = {
        "default_route": {"gateway": "192.168.32.2", "interface": "ens38"},
        "default_routes": [
            {"gateway": "192.168.32.2", "interface": "ens38", "metric": 100},
        ],
        "dhcp_leases": [
            {
                "interface": "ens37",
                "routers": ["10.11.11.11"],
                "source": "systemd-networkd-lease",
            }
        ],
    }

    candidates = _candidate_gateways(environment, "ens37")

    assert candidates == [
        {
            "address": "10.11.11.11",
            "provenance": "dhcp-lease-router",
            "source": "systemd-networkd-lease",
        }
    ]
