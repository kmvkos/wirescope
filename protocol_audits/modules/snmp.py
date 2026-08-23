"""Unauthenticated SNMPv3 presence probe. No community guessing."""

from config.settings import Settings
from parsers.protocol.snmp import parse_snmpget
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import canonical_host
from providers.tools import ToolCommand, ToolResult


SNMP_USER = "wirescope-unauth"
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"


class SnmpModule(ProtocolModule):
    name = "snmp"
    protocol = "snmp"
    safety = SafetyClass.SAFE
    required_tool = "snmpget"
    timeout_seconds = 8.0
    version_args = ("-V",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({161}),
            protocols=frozenset({"udp"}),
            service_names=frozenset({"snmp"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.snmpget_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        host = canonical_host(target.address)
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=[
                    "-v3",
                    "-l",
                    "noAuthNoPriv",
                    "-u",
                    SNMP_USER,
                    "-t",
                    "2",
                    "-r",
                    "0",
                    host,
                    SYS_DESCR_OID,
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
        return parse_snmpget(result)
