"""Anonymous LDAP base DSE observations. No authenticated AD audit."""

from config.settings import Settings
from parsers.protocol.ldap import parse_ldapsearch
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import bracket_host
from providers.tools import ToolCommand, ToolResult


class LdapModule(ProtocolModule):
    name = "ldap"
    protocol = "ldap"
    safety = SafetyClass.SAFE
    required_tool = "ldapsearch"
    timeout_seconds = 12.0
    version_args = ("-VV",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({389}),
            service_names=frozenset({"ldap"}),
        ),
        ServicePredicate(
            ports=frozenset({636}),
            service_names=frozenset({"ldaps", "ldapssl"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.ldapsearch_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        scheme = "ldaps" if _uses_tls(target) else "ldap"
        uri = f"{scheme}://{bracket_host(target.address)}:{target.port}"
        args = [
            "-x",
            "-LLL",
            "-H",
            uri,
            "-s",
            "base",
            "-b",
            "",
            "-l",
            "8",
            "namingContexts",
            "defaultNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "supportedLDAPVersion",
        ]
        if scheme == "ldaps":
            args.extend(["-o", "tls_reqcert=allow"])
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=args,
                timeout_seconds=self.command_timeout(settings),
                environment={"LC_ALL": "C"},
            )
        ]

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        return parse_ldapsearch(result)


def _uses_tls(target: ProbeTarget) -> bool:
    name = (target.service.service_name or "").lower()
    tunnel = (target.service.tunnel or "").lower()
    return (
        target.port == 636
        or name in {"ldaps", "ldapssl"}
        or tunnel in {"ssl", "tls"}
    )
