"""Route and source-address validation for authorized active scope."""

from enum import Enum
import ipaddress
import json
from typing import Any

from pydantic import BaseModel, Field

from engine.interfaces import InterfaceInfo, InterfaceService
from engine.scope import ScopeTarget, ValidatedScope
from providers.tools import ToolCommand, ToolRunner


class RouteValidationCode(str, Enum):
    ADDRESS_FAMILY_UNAVAILABLE = "address_family_unavailable"
    ROUTE_LOOKUP_FAILED = "route_lookup_failed"
    ROUTE_DATA_INVALID = "route_data_invalid"
    INTERFACE_MISMATCH = "route_interface_mismatch"
    SOURCE_ADDRESS_MISSING = "source_address_missing"
    SOURCE_FAMILY_MISMATCH = "source_family_mismatch"


class RouteValidationError(ValueError):
    def __init__(
        self,
        code: RouteValidationCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class TargetRoute(BaseModel):
    target: str
    representative_address: str
    family: int = Field(ge=4, le=6)
    interface: str
    source_address: str
    gateway: str | None = None
    directly_connected: bool


class ResolvedScope(BaseModel):
    interface: str
    interface_state: str | None
    vlan_subinterface: bool
    routes: list[TargetRoute]


class RouteResolver:
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        interfaces: InterfaceService | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.interfaces = interfaces or InterfaceService(runner=self.runner)

    def resolve(
        self,
        interface_name: str,
        scope: ValidatedScope,
    ) -> ResolvedScope:
        interface = self.interfaces.validate(interface_name)
        usable_families: set[int] = set()
        missing_families: list[int] = []
        for family in scope.address_families:
            addresses = interface.ipv4 if family == 4 else interface.ipv6
            if addresses:
                usable_families.add(family)
            else:
                missing_families.append(family)
        if not usable_families:
            family = missing_families[0] if missing_families else 4
            raise RouteValidationError(
                RouteValidationCode.ADDRESS_FAMILY_UNAVAILABLE,
                (
                    f"Interface {interface.name} has no IPv{family} "
                    "source address"
                ),
                details={"interface": interface.name, "family": family},
            )

        routes: list[TargetRoute] = []
        errors: list[RouteValidationError] = []
        for target in scope.targets:
            if target.family not in usable_families:
                continue
            try:
                routes.append(self._resolve_target(interface, target))
            except RouteValidationError as exc:
                errors.append(exc)
        if not routes:
            if errors:
                raise errors[0]
            family = (
                missing_families[0]
                if missing_families
                else scope.address_families[0]
            )
            raise RouteValidationError(
                RouteValidationCode.ADDRESS_FAMILY_UNAVAILABLE,
                (
                    f"Interface {interface.name} has no IPv{family} "
                    "source address"
                ),
                details={"interface": interface.name, "family": family},
            )
        return ResolvedScope(
            interface=interface.name,
            interface_state=interface.state,
            vlan_subinterface="." in interface.name,
            routes=routes,
        )

    def _resolve_target(
        self,
        interface: InterfaceInfo,
        target: ScopeTarget,
    ) -> TargetRoute:
        network = ipaddress.ip_network(
            (
                target.value
                if "/" in target.value
                else f"{target.value}/{32 if target.family == 4 else 128}"
            ),
            strict=True,
        )
        representative = self._representative_address(network, interface)
        result = self.runner.run(
            ToolCommand(
                tool="ip",
                args=[
                    "-j",
                    f"-{target.family}",
                    "route",
                    "get",
                    representative,
                ],
                timeout_seconds=5,
            )
        )
        if not result.success:
            raise RouteValidationError(
                RouteValidationCode.ROUTE_LOOKUP_FAILED,
                f"No usable route to {target.value}",
                details={"target": target.value},
            )
        try:
            payload = json.loads(result.stdout)
            route = payload[0]
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            raise RouteValidationError(
                RouteValidationCode.ROUTE_DATA_INVALID,
                f"Route lookup returned invalid data for {target.value}",
            ) from exc

        route_interface = route.get("dev")
        source = route.get("prefsrc") or route.get("src")
        if self._is_local_route(route) and self._belongs_to_interface_network(
            representative,
            interface,
        ):
            route_interface = interface.name
            source = source or representative
        if route_interface != interface.name:
            raise RouteValidationError(
                RouteValidationCode.INTERFACE_MISMATCH,
                (
                    f"Route to {target.value} uses {route_interface or 'none'}, "
                    f"not selected interface {interface.name}"
                ),
                details={
                    "target": target.value,
                    "selected_interface": interface.name,
                    "route_interface": route_interface,
                },
            )
        if not source:
            raise RouteValidationError(
                RouteValidationCode.SOURCE_ADDRESS_MISSING,
                f"Route to {target.value} has no source address",
            )
        try:
            source_family = ipaddress.ip_address(source).version
        except ValueError as exc:
            raise RouteValidationError(
                RouteValidationCode.ROUTE_DATA_INVALID,
                f"Route source address is invalid: {source}",
            ) from exc
        if source_family != target.family:
            raise RouteValidationError(
                RouteValidationCode.SOURCE_FAMILY_MISMATCH,
                f"Route source family does not match {target.value}",
            )

        gateway = route.get("gateway")
        return TargetRoute(
            target=target.value,
            representative_address=representative,
            family=target.family,
            interface=interface.name,
            source_address=source,
            gateway=gateway,
            directly_connected=(
                gateway is None
                and self._belongs_to_interface_network(
                    representative,
                    interface,
                )
            ),
        )

    @staticmethod
    def _belongs_to_interface_network(
        address: str,
        interface: InterfaceInfo,
    ) -> bool:
        parsed = ipaddress.ip_address(address)
        values = interface.ipv4 if parsed.version == 4 else interface.ipv6
        return any(
            parsed in ipaddress.ip_interface(value).network
            for value in values
        )

    @staticmethod
    def _is_local_route(route: dict[str, Any]) -> bool:
        flags = route.get("flags") or []
        if not isinstance(flags, list):
            flags = []
        return (
            route.get("type") == "local"
            or "local" in {str(flag).lower() for flag in flags}
            or str(route.get("dev") or "") == "lo"
        )

    @staticmethod
    def _representative_address(
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        interface: InterfaceInfo,
    ) -> str:
        if network.prefixlen == network.max_prefixlen:
            return str(network.network_address)
        assigned: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        values = interface.ipv4 if network.version == 4 else interface.ipv6
        for value in values:
            try:
                assigned.add(ipaddress.ip_interface(value).ip)
            except ValueError:
                continue
        for candidate in network.hosts():
            if candidate not in assigned:
                return str(candidate)
        try:
            return str(next(network.hosts()))
        except StopIteration:
            return str(network.network_address)
