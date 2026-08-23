"""Unauthenticated, non-destructive SMB probes via smbclient.

enum4linux-ng and credential guessing are not used. The default probe is a
null-session share list that records acceptance or refusal.
"""

from config.settings import Settings
from parsers.protocol.smb import parse_smbclient
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import bracket_host, canonical_host
from providers.tools import ToolCommand, ToolResult


class SmbModule(ProtocolModule):
    name = "smb"
    protocol = "smb"
    safety = SafetyClass.SAFE
    required_tool = "smbclient"
    timeout_seconds = 15.0
    version_args = ("-V",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({139, 445}),
            service_names=frozenset({"microsoft-ds", "netbios-ssn", "smb"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.smbclient_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        host = canonical_host(target.address)
        share_target = f"//{bracket_host(host)}"
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=[
                    "-N",
                    "-L",
                    share_target,
                    "-p",
                    str(target.port),
                    "-m",
                    "SMB3",
                ],
                timeout_seconds=self.command_timeout(settings),
                environment={"LC_ALL": "C"},
            )
        ]

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        return parse_smbclient(result)
