"""Non-intrusive SSH fingerprinting via ssh-audit."""

from config.settings import Settings
from parsers.protocol.ssh import parse_ssh_audit
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import canonical_host
from providers.tools import ToolCommand, ToolResult


class SshModule(ProtocolModule):
    name = "ssh"
    protocol = "ssh"
    safety = SafetyClass.SAFE
    required_tool = "ssh-audit"
    min_version = "2.0"
    timeout_seconds = 20.0
    version_args = ("--version",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({22}),
            service_names=frozenset({"ssh"}),
            products=frozenset({"openssh", "dropbear"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.ssh_audit_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        host = canonical_host(target.address)
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=["-n", "-p", str(target.port), host],
                timeout_seconds=self.command_timeout(settings),
                environment={"LC_ALL": "C"},
            )
        ]

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        return parse_ssh_audit(result)
