"""Network interface discovery and reusable capture policy validation."""

from enum import Enum
import json
from pathlib import Path

from pydantic import BaseModel, Field

from config.settings import Settings, get_settings
from providers.tools import ToolCommand, ToolResult, ToolRunner


class InterfaceValidationCode(str, Enum):
    DISCOVERY_FAILED = "discovery_failed"
    INVALID_DISCOVERY_DATA = "invalid_discovery_data"
    UNKNOWN_INTERFACE = "unknown_interface"
    LOOPBACK_DENIED = "loopback_denied"
    NOT_ALLOWED = "not_allowed"
    LINK_NOT_UP = "link_not_up"


class InterfaceValidationError(ValueError):
    def __init__(
        self,
        code: InterfaceValidationCode,
        message: str,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InterfaceInfo(BaseModel):
    name: str = Field(min_length=1)
    state: str | None = None
    mac: str | None = None
    mtu: int | None = None
    speed_mbps: int | None = None
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    is_loopback: bool = False
    allowed: bool = False
    denial_reason: InterfaceValidationCode | None = None


class InterfaceDiscoveryResult(BaseModel):
    interfaces: list[InterfaceInfo] = Field(default_factory=list)
    tool_result: ToolResult


class InterfaceService:
    def __init__(
        self,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
        sys_class_net: Path = Path("/sys/class/net"),
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()
        self.sys_class_net = sys_class_net

    def discover(self) -> InterfaceDiscoveryResult:
        tool_result = self.runner.run(
            ToolCommand(
                tool="ip",
                args=["-j", "addr"],
                timeout_seconds=5,
            )
        )
        if not tool_result.success:
            message = (
                tool_result.error.message
                if tool_result.error
                else "Interface discovery failed"
            )
            raise InterfaceValidationError(
                InterfaceValidationCode.DISCOVERY_FAILED,
                message,
            )

        try:
            payload = json.loads(tool_result.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise InterfaceValidationError(
                InterfaceValidationCode.INVALID_DISCOVERY_DATA,
                f"iproute2 returned invalid interface JSON: {exc}",
            ) from exc

        if not isinstance(payload, list):
            raise InterfaceValidationError(
                InterfaceValidationCode.INVALID_DISCOVERY_DATA,
                "iproute2 interface JSON must be a list",
            )

        interfaces = [
            self._normalize_interface(item)
            for item in payload
            if isinstance(item, dict) and item.get("ifname")
        ]
        return InterfaceDiscoveryResult(
            interfaces=interfaces,
            tool_result=tool_result,
        )

    def validate(self, interface_name: str) -> InterfaceInfo:
        discovery = self.discover()
        interface = next(
            (
                item
                for item in discovery.interfaces
                if item.name == interface_name
            ),
            None,
        )
        if interface is None:
            raise InterfaceValidationError(
                InterfaceValidationCode.UNKNOWN_INTERFACE,
                f"Unknown network interface: {interface_name}",
            )
        if interface.denial_reason is not None:
            messages = {
                InterfaceValidationCode.LOOPBACK_DENIED:
                    "Loopback interfaces are disabled by policy",
                InterfaceValidationCode.NOT_ALLOWED:
                    "Interface is not in the configured allowlist",
                InterfaceValidationCode.LINK_NOT_UP:
                    "Interface link state is not UP",
            }
            raise InterfaceValidationError(
                interface.denial_reason,
                messages[interface.denial_reason],
            )
        return interface

    def _normalize_interface(self, item: dict) -> InterfaceInfo:
        name = str(item["ifname"])
        flags = {str(flag).upper() for flag in item.get("flags", [])}
        is_loopback = (
            name == "lo"
            or "LOOPBACK" in flags
            or item.get("link_type") == "loopback"
        )
        state = item.get("operstate")
        allowed_names = self.settings.allowed_interfaces

        denial_reason = None
        if is_loopback and not self.settings.allow_loopback:
            denial_reason = InterfaceValidationCode.LOOPBACK_DENIED
        elif allowed_names and name not in allowed_names:
            denial_reason = InterfaceValidationCode.NOT_ALLOWED
        elif (
            self.settings.require_interface_up
            and str(state).upper() != "UP"
        ):
            denial_reason = InterfaceValidationCode.LINK_NOT_UP

        ipv4: list[str] = []
        ipv6: list[str] = []
        for address in item.get("addr_info", []):
            local = address.get("local")
            prefix = address.get("prefixlen")
            if local is None or prefix is None:
                continue
            value = f"{local}/{prefix}"
            if address.get("family") == "inet":
                ipv4.append(value)
            elif address.get("family") == "inet6":
                ipv6.append(value)

        return InterfaceInfo(
            name=name,
            state=state,
            mac=item.get("address"),
            mtu=item.get("mtu"),
            speed_mbps=self._interface_speed(name),
            ipv4=ipv4,
            ipv6=ipv6,
            is_loopback=is_loopback,
            allowed=denial_reason is None,
            denial_reason=denial_reason,
        )

    def _interface_speed(self, interface_name: str) -> int | None:
        speed_path = self.sys_class_net / interface_name / "speed"
        try:
            speed = speed_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return int(speed) if speed.isdigit() else None
