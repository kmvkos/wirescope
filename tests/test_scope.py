from dataclasses import replace

import pytest

from engine.scope import (
    ActiveProfile,
    ScopeProposalSource,
    ScopeValidationCode,
    ScopeValidator,
    expand_connected_network_targets,
)


def validator(durable_settings, **overrides):
    return ScopeValidator(replace(durable_settings, **overrides))


def test_single_ipv4(durable_settings):
    scope = validator(durable_settings).validate(
        ["192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    assert scope.canonical_targets == ["192.0.2.10"]
    assert scope.address_count == 1
    assert scope.address_families == [4]


def test_ipv4_cidr_and_multiple_targets(durable_settings):
    scope = validator(durable_settings).validate(
        ["192.0.2.0/24", "198.51.100.8", "192.0.2.10"],
        ActiveProfile.STANDARD,
    )
    assert "192.0.2.0/24" in scope.canonical_targets
    assert "198.51.100.8" in scope.canonical_targets
    assert "192.0.2.10" not in scope.canonical_targets
    assert scope.address_count == 257


def test_single_ipv6_and_cidr(durable_settings):
    scope = validator(durable_settings).validate(
        ["2001:db8::10", "2001:db8:1::/126"],
        ActiveProfile.DISCOVERY,
    )
    assert scope.address_families == [6]
    assert scope.address_count == 5


def test_invalid_address_and_malformed_cidr(durable_settings):
    with pytest.raises(Exception) as invalid:
        validator(durable_settings).validate(
            ["not-an-ip"],
            ActiveProfile.STANDARD,
        )
    assert invalid.value.code == ScopeValidationCode.INVALID_TARGET
    with pytest.raises(Exception) as cidr:
        validator(durable_settings).validate(
            ["192.0.2.0/33"],
            ActiveProfile.STANDARD,
        )
    assert cidr.value.code == ScopeValidationCode.INVALID_TARGET


def test_default_route_and_unspecified_are_prohibited(durable_settings):
    for target in ("0.0.0.0/0", "::/0", "224.0.0.1"):
        with pytest.raises(Exception) as exc:
            validator(durable_settings).validate(
                [target],
                ActiveProfile.DEEP,
            )
        assert exc.value.code == ScopeValidationCode.PROHIBITED_TARGET


def test_scope_over_configured_limit(durable_settings):
    with pytest.raises(Exception) as exc:
        validator(durable_settings).validate(
            ["10.0.0.0/8"],
            ActiveProfile.STANDARD,
        )
    assert exc.value.code == ScopeValidationCode.LIMIT_EXCEEDED
    with pytest.raises(Exception):
        validator(durable_settings).validate(
            ["192.0.2.0/22"],
            ActiveProfile.DEEP,
        )


def test_administrator_can_raise_scope_limits(durable_settings):
    scope = validator(
        durable_settings,
        active_allow_large_scopes=True,
    ).validate(["10.0.0.0/16"], ActiveProfile.DISCOVERY)
    assert scope.address_count == 65_536


def test_propose_derives_prefix_from_interface_address(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=["192.168.32.149/24", "2001:db8::10/126", "fe80::1/64"],
        peers=[],
        routes=[],
    )
    assert proposal.source == ScopeProposalSource.INTERFACE_PREFIX
    assert proposal.canonical_targets == ["192.168.32.0/24", "2001:db8::10/126"]
    assert proposal.assigned_addresses == [
        "192.168.32.149/24",
        "2001:db8::10/126",
    ]
    assert any(item.code == "not_global_unicast" for item in proposal.rejected)


def test_propose_ipv6_oversize_prefix_is_rejected(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=["2001:db8::10/64"],
        peers=[],
        routes=[],
    )
    assert proposal.source == ScopeProposalSource.EMPTY
    assert proposal.canonical_targets == []
    assert proposal.rejected[0].code == ScopeValidationCode.LIMIT_EXCEEDED.value


def test_propose_keeps_ipv4_when_ipv6_ula_prefix_is_oversize(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="ens37",
        assigned=[
            "10.11.11.124/24",
            "fdf3:e41b:5dc3:0:c6af:daba:6a30:f2ee/64",
            "fe80::d7a9:bc60:c9fa:2216/64",
        ],
        peers=[],
        routes=[],
    )
    assert proposal.source == ScopeProposalSource.INTERFACE_PREFIX
    assert proposal.canonical_targets == ["10.11.11.0/24"]
    assert "fdf3:e41b:5dc3:0:c6af:daba:6a30:f2ee" not in proposal.canonical_targets
    codes = {item.code for item in proposal.rejected}
    assert ScopeValidationCode.LIMIT_EXCEEDED.value in codes
    assert "not_global_unicast" in codes


def test_expand_connected_network_address_to_prefix():
    assert expand_connected_network_targets(
        ["10.11.11.0", "10.11.11.82"],
        assigned=["10.11.11.124/24"],
    ) == ["10.11.11.0/24", "10.11.11.82"]


def test_propose_uses_vlan_subinterface_when_no_l3(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=[],
        peers=[
            {
                "name": "eth0.20",
                "ipv4": ["10.20.0.5/24"],
                "ipv6": [],
            }
        ],
        routes=[{"dst": "default", "dev": "eth0"}],
    )
    assert proposal.source == ScopeProposalSource.VLAN_HINTS
    assert proposal.interface == "eth0.20"
    assert proposal.canonical_targets == ["10.20.0.0/24"]
    assert proposal.vlan_ids == [20]


def test_propose_uses_connected_route_when_no_address_or_vlan(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=[],
        peers=[],
        routes=[
            {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"},
            {"dst": "10.8.0.0/24", "dev": "eth0", "protocol": "kernel"},
        ],
    )
    assert proposal.source == ScopeProposalSource.ROUTE_HINTS
    assert proposal.canonical_targets == ["10.8.0.0/24"]
    assert "0.0.0.0/0" not in proposal.canonical_targets
    assert "::/0" not in proposal.canonical_targets


def test_propose_ignores_management_prefixes_for_capture_nic(durable_settings):
    proposal = validator(durable_settings).propose(
        interface_name="eth1",
        assigned=[],
        peers=[
            {
                "name": "eth0",
                "ipv4": ["192.168.32.149/24"],
                "ipv6": [],
            }
        ],
        routes=[
            {"dst": "default", "dev": "eth0", "gateway": "192.168.32.2"},
            {"dst": "192.168.32.0/24", "dev": "eth0"},
        ],
        management_names={"eth0"},
    )
    assert proposal.source == ScopeProposalSource.EMPTY
    assert proposal.canonical_targets == []
    assert "192.168.32.0/24" not in proposal.canonical_targets
    assert proposal.uses_management_interface is False


def test_propose_never_includes_unspecified_or_oversize(durable_settings):
    unspecified = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=["0.0.0.0/0", "::/0"],
        peers=[],
        routes=[],
    )
    assert unspecified.source == ScopeProposalSource.EMPTY
    assert unspecified.canonical_targets == []
    assert {
        item.code for item in unspecified.rejected
    } == {ScopeValidationCode.PROHIBITED_TARGET.value}

    oversize = validator(
        durable_settings,
        active_allow_large_scopes=False,
        active_discovery_max_targets=256,
        active_standard_max_targets=256,
        active_deep_max_targets=256,
    ).propose(
        interface_name="eth0",
        assigned=["10.0.0.0/8"],
        peers=[],
        routes=[],
    )
    assert oversize.canonical_targets == []
    assert oversize.rejected[0].code == ScopeValidationCode.LIMIT_EXCEEDED.value

    default_only = validator(durable_settings).propose(
        interface_name="eth0",
        assigned=[],
        peers=[],
        routes=[
            {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"},
            {"dst": "0.0.0.0/0", "dev": "eth0"},
            {"dst": "10.0.0.0/8", "dev": "eth0", "gateway": "192.0.2.1"},
        ],
    )
    assert default_only.source == ScopeProposalSource.EMPTY
    assert default_only.canonical_targets == []
