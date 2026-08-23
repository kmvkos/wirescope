"""Protocol-audit plugin contract.

Adding a module must not require changes to the job orchestrator beyond
registering it. Command builders return argv lists only; they never use a
shell and never interpolate untrusted strings.
"""

from abc import ABC, abstractmethod

from config.settings import Settings
from inventory.models import ServiceRecord
from protocol_audits.availability import inspect_tool, settings_timeout
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
    ToolAvailability,
)
from providers.tools import ToolCommand, ToolResult, ToolRunner


class ProtocolModule(ABC):
    name: str
    protocol: str
    safety: SafetyClass = SafetyClass.SAFE
    required_tool: str
    min_version: str | None = None
    timeout_seconds: float = 20.0
    version_args: tuple[str, ...] = ("--version",)
    predicates: tuple[ServicePredicate, ...] = ()
    parse_on_nonzero_exit: bool = True

    def matches(self, service: ServiceRecord) -> bool:
        return any(predicate.matches(service) for predicate in self.predicates)

    def tool_name(self, settings: Settings) -> str:
        return self.required_tool

    def availability(
        self,
        runner: ToolRunner,
        settings: Settings,
    ) -> ToolAvailability:
        return inspect_tool(
            tool=self.tool_name(settings),
            runner=runner,
            version_args=self.version_args,
            minimum_version=self.min_version,
        )

    def command_timeout(self, settings: Settings) -> float:
        return settings_timeout(settings, self.timeout_seconds)

    @abstractmethod
    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        ...

    def build_command(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> ToolCommand:
        commands = self.build_commands(target, settings)
        if len(commands) != 1:
            raise RuntimeError(
                f"{self.name} must override build_commands for multi-command probes"
            )
        return commands[0]

    @abstractmethod
    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        ...

    def parse_results(
        self,
        results: list[ToolResult],
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        observations: list[ObservationDraft] = []
        for result in results:
            observations.extend(self.parse(result, target))
        return observations

    def command_metadata(self, commands: list[ToolCommand]) -> dict[str, object]:
        return {
            "tool": self.required_tool,
            "command_count": len(commands),
            "arg_counts": [len(command.argv) for command in commands],
            "timeout_seconds": [
                command.timeout_seconds for command in commands
            ],
        }
