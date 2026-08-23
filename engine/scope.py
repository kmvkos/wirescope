"""Authorized active-scan scope validation and canonicalization."""

from enum import Enum
import ipaddress
from typing import Any

from pydantic import BaseModel, Field

from config.settings import Settings


class ActiveProfile(str, Enum):
    DISCOVERY = "discovery"
    STANDARD = "standard"
    DEEP = "deep"


class ScopeValidationCode(str, Enum):
    EMPTY = "empty_scope"
    INVALID_TARGET = "invalid_target"
    PROHIBITED_TARGET = "prohibited_target"
    TOO_MANY_EXPRESSIONS = "too_many_scope_expressions"
    LIMIT_EXCEEDED = "scope_limit_exceeded"


class ScopeValidationError(ValueError):
    def __init__(
        self,
        code: ScopeValidationCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class ScopeTarget(BaseModel):
    value: str
    family: int = Field(ge=4, le=6)
    kind: str
    address_count: int = Field(ge=1)


class ValidatedScope(BaseModel):
    profile: ActiveProfile
    targets: list[ScopeTarget]
    canonical_targets: list[str]
    address_families: list[int]
    address_count: int = Field(ge=1)
    safety_limits: dict[str, int]


class ScopeValidator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def validate(
        self,
        targets: list[str],
        profile: ActiveProfile,
    ) -> ValidatedScope:
        if not targets:
            raise ScopeValidationError(
                ScopeValidationCode.EMPTY,
                "At least one active target is required",
            )
        if len(targets) > 256:
            raise ScopeValidationError(
                ScopeValidationCode.TOO_MANY_EXPRESSIONS,
                "Active scope contains more than 256 expressions",
            )

        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw_target in targets:
            networks.append(self._parse_target(raw_target))
        networks = self._remove_duplicates_and_covered(networks)

        family_counts = {
            family: sum(
                network.num_addresses
                for network in networks
                if network.version == family
            )
            for family in (4, 6)
        }
        address_count = sum(family_counts.values())
        safety_limits = {
            "ipv4": self._profile_limit(profile),
            "ipv6": min(
                self._profile_limit(profile),
                self.settings.active_ipv6_max_targets,
            ),
        }
        exceeded = {
            family: family_counts[family]
            for family, name in ((4, "ipv4"), (6, "ipv6"))
            if family_counts[family] > safety_limits[name]
        }
        if not self.settings.active_allow_large_scopes and exceeded:
            raise ScopeValidationError(
                ScopeValidationCode.LIMIT_EXCEEDED,
                (
                    f"{profile.value} scope contains {address_count} addresses; "
                    "one or more address-family limits were exceeded"
                ),
                details={
                    "address_count": address_count,
                    "family_counts": family_counts,
                    "limits": safety_limits,
                    "profile": profile.value,
                },
            )

        normalized_targets = [
            ScopeTarget(
                value=self._display_value(network),
                family=network.version,
                kind=(
                    "single"
                    if network.prefixlen == network.max_prefixlen
                    else "cidr"
                ),
                address_count=network.num_addresses,
            )
            for network in networks
        ]
        return ValidatedScope(
            profile=profile,
            targets=normalized_targets,
            canonical_targets=[target.value for target in normalized_targets],
            address_families=sorted(
                {target.family for target in normalized_targets}
            ),
            address_count=address_count,
            safety_limits=safety_limits,
        )

    def _profile_limit(self, profile: ActiveProfile) -> int:
        return {
            ActiveProfile.DISCOVERY:
                self.settings.active_discovery_max_targets,
            ActiveProfile.STANDARD:
                self.settings.active_standard_max_targets,
            ActiveProfile.DEEP:
                self.settings.active_deep_max_targets,
        }[profile]

    @staticmethod
    def _parse_target(
        raw_target: str,
    ) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        value = raw_target.strip()
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=True)
            else:
                address = ipaddress.ip_address(value)
                network = ipaddress.ip_network(
                    f"{address}/{address.max_prefixlen}",
                    strict=True,
                )
        except ValueError as exc:
            raise ScopeValidationError(
                ScopeValidationCode.INVALID_TARGET,
                f"Invalid IP target: {raw_target}",
            ) from exc

        if network.prefixlen == 0 or network.is_unspecified or network.is_multicast:
            raise ScopeValidationError(
                ScopeValidationCode.PROHIBITED_TARGET,
                f"Unspecified or multicast target is prohibited: {raw_target}",
            )
        return network

    @staticmethod
    def _remove_duplicates_and_covered(
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        ordered = sorted(
            set(networks),
            key=lambda item: (
                item.version,
                int(item.network_address),
                item.prefixlen,
            ),
        )
        result: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for network in ordered:
            if any(
                network.version == existing.version
                and network.subnet_of(existing)
                for existing in result
            ):
                continue
            result.append(network)
        return result

    @staticmethod
    def _display_value(
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> str:
        if network.prefixlen == network.max_prefixlen:
            return str(network.network_address)
        return str(network)
