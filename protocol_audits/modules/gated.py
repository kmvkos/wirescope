"""Explicitly gated optional scanners. They are never dispatched in Milestone 4."""

from config.settings import Settings
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ToolAvailability,
)
from protocol_audits.modules.base import ProtocolModule
from providers.tools import ToolCommand, ToolResult, ToolRunner


class GatedModule(ProtocolModule):
    safety = SafetyClass.NEVER_DEFAULT
    predicates = ()
    timeout_seconds = 1.0
    required_tool = "gated"

    def availability(
        self,
        runner: ToolRunner,
        settings: Settings,
    ) -> ToolAvailability:
        return ToolAvailability(
            tool=self.required_tool,
            available=False,
            meets_minimum=False,
            message=(
                f"{self.name} is gated off in Milestone 4 and is not a "
                "default protocol-audit module"
            ),
        )

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        raise RuntimeError(f"{self.name} is gated off and cannot build commands")

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        raise RuntimeError(f"{self.name} is gated off and cannot parse output")


class TestsslModule(GatedModule):
    name = "testssl"
    protocol = "tls"
    required_tool = "testssl.sh"


class NiktoModule(GatedModule):
    name = "nikto"
    protocol = "http"
    required_tool = "nikto"


class NucleiModule(GatedModule):
    name = "nuclei"
    protocol = "http"
    required_tool = "nuclei"
