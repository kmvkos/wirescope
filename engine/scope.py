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

    def propose(
        self,
        *,
        interface_name: str,
        assigned: list[str],
        peers: list[dict[str, Any]] | None = None,
        routes: list[dict[str, Any]] | None = None,
        management_names: set[str] | None = None,
    ) -> "ScopeProposal":
        rejected: list[RejectedCandidate] = []
        management = set(management_names or ())
        uses_management = interface_name in management
        selected = _eligible_networks(
            self,
            assigned,
            origin="assigned",
            interface_name=interface_name,
            rejected=rejected,
        )
        if selected:
            return _proposal(
                interface_name=interface_name,
                source=ScopeProposalSource.INTERFACE_PREFIX,
                networks=selected,
                rejected=rejected,
                uses_management_interface=uses_management,
            )

        vlan_by_iface: dict[str, list[ProposedNetwork]] = {}
        for peer in peers or []:
            name = str(peer.get("name") or "")
            if name in management:
                continue
            vlan_id = _vlan_id_for(interface_name, name)
            if vlan_id is None:
                continue
            addresses = [
                *list(peer.get("ipv4") or []),
                *list(peer.get("ipv6") or []),
            ]
            child_networks = _eligible_networks(
                self,
                addresses,
                origin="vlan",
                interface_name=name,
                vlan_id=vlan_id,
                rejected=rejected,
            )
            if child_networks:
                vlan_by_iface.setdefault(name, []).extend(child_networks)
        if vlan_by_iface:
            chosen_iface = next(iter(vlan_by_iface))
            return _proposal(
                interface_name=chosen_iface,
                source=ScopeProposalSource.VLAN_HINTS,
                networks=vlan_by_iface[chosen_iface],
                rejected=rejected,
                uses_management_interface=uses_management,
            )

        route_networks: list[ProposedNetwork] = []
        for route in routes or []:
            device = str(route.get("dev") or "")
            if device != interface_name:
                continue
            if device in management and not uses_management:
                continue
            if route.get("gateway"):
                continue
            destination = _route_destination(route)
            if destination is None:
                continue
            route_networks.extend(
                _eligible_networks(
                    self,
                    [destination],
                    origin="route",
                    interface_name=interface_name,
                    rejected=rejected,
                )
            )
        if route_networks:
            return _proposal(
                interface_name=interface_name,
                source=ScopeProposalSource.ROUTE_HINTS,
                networks=route_networks,
                rejected=rejected,
                uses_management_interface=uses_management,
            )

        return _proposal(
            interface_name=interface_name,
            source=ScopeProposalSource.EMPTY,
            networks=[],
            rejected=rejected,
            uses_management_interface=uses_management,
        )

    def _proposal_limit(self, version: int) -> int:
        limit = max(
            self.settings.active_discovery_max_targets,
            self.settings.active_standard_max_targets,
            self.settings.active_deep_max_targets,
        )
        if version == 6:
            return min(limit, self.settings.active_ipv6_max_targets)
        return limit


class ScopeProposalSource(str, Enum):
    INTERFACE_PREFIX = "interface_prefix"
    VLAN_HINTS = "vlan_hints"
    ROUTE_HINTS = "route_hints"
    EMPTY = "empty"


class ProposedNetwork(BaseModel):
    cidr: str
    origin: str
    assigned: str | None = None
    vlan_id: int | None = None
    interface: str | None = None


class RejectedCandidate(BaseModel):
    value: str
    code: str


class ScopeProposal(BaseModel):
    interface: str
    source: ScopeProposalSource
    networks: list[ProposedNetwork]
    canonical_targets: list[str]
    assigned_addresses: list[str]
    vlan_ids: list[int]
    rejected: list[RejectedCandidate]
    uses_management_interface: bool = False


def _proposal(
    *,
    interface_name: str,
    source: ScopeProposalSource,
    networks: list[ProposedNetwork],
    rejected: list[RejectedCandidate],
    uses_management_interface: bool = False,
) -> ScopeProposal:
    unique: list[ProposedNetwork] = []
    seen: set[str] = set()
    for item in networks:
        if item.cidr in seen:
            continue
        seen.add(item.cidr)
        unique.append(item)
    return ScopeProposal(
        interface=interface_name,
        source=source,
        networks=unique,
        canonical_targets=[item.cidr for item in unique],
        assigned_addresses=[
            item.assigned for item in unique if item.assigned
        ],
        vlan_ids=sorted(
            {
                item.vlan_id
                for item in unique
                if item.vlan_id is not None
            }
        ),
        rejected=rejected,
        uses_management_interface=uses_management_interface,
    )


def _eligible_networks(
    validator: ScopeValidator,
    values: list[str],
    *,
    origin: str,
    interface_name: str,
    rejected: list[RejectedCandidate],
    vlan_id: int | None = None,
) -> list[ProposedNetwork]:
    found: list[ProposedNetwork] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            network = _assigned_network(value)
        except ScopeValidationError as exc:
            rejected.append(RejectedCandidate(value=value, code=exc.code.value))
            continue
        if network.is_loopback or network.is_link_local:
            rejected.append(
                RejectedCandidate(value=value, code="not_global_unicast")
            )
            continue
        if (
            not validator.settings.active_allow_large_scopes
            and network.num_addresses > validator._proposal_limit(network.version)
        ):
            host = (
                _host_fallback(value)
                if origin == "assigned" and network.version == 6
                else None
            )
            if host is None:
                rejected.append(
                    RejectedCandidate(
                        value=value,
                        code=ScopeValidationCode.LIMIT_EXCEEDED.value,
                    )
                )
                continue
            network = host
        found.append(
            ProposedNetwork(
                cidr=ScopeValidator._display_value(network),
                origin=origin,
                assigned=value if origin == "assigned" else None,
                vlan_id=vlan_id,
                interface=interface_name,
            )
        )
    return found


def _assigned_network(
    raw: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    value = raw.strip()
    try:
        if "/" in value:
            network = ipaddress.ip_interface(value).network
        else:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(
                f"{address}/{address.max_prefixlen}",
                strict=True,
            )
    except ValueError as exc:
        raise ScopeValidationError(
            ScopeValidationCode.INVALID_TARGET,
            f"Invalid IP target: {raw}",
        ) from exc
    if network.prefixlen == 0 or network.is_unspecified or network.is_multicast:
        raise ScopeValidationError(
            ScopeValidationCode.PROHIBITED_TARGET,
            f"Unspecified or multicast target is prohibited: {raw}",
        )
    return network


def _vlan_id_for(parent: str, child: str) -> int | None:
    name = child.split("@", 1)[0]
    prefix = f"{parent}."
    if not name.startswith(prefix):
        return None
    suffix = name[len(prefix):]
    if suffix.isdigit():
        vlan_id = int(suffix)
        if 0 <= vlan_id <= 4095:
            return vlan_id
    return None


def _host_fallback(
    raw: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    host = raw.split("/", 1)[0].strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return None
    if address.is_link_local:
        return None
    return ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)


def _route_destination(route: dict[str, Any]) -> str | None:
    destination = route.get("dst")
    if destination in (None, "", "default", "unspecified", "0.0.0.0/0", "::/0"):
        return None
    return str(destination)
