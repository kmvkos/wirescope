from dataclasses import replace

import pytest

from engine.scope import ActiveProfile, ScopeValidationCode, ScopeValidator


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
