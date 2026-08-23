"""Direct TLS handshake observations via OpenSSL s_client."""

from config.settings import Settings
from parsers.protocol.tls import parse_openssl_sclient
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import connect_endpoint, safe_hostname
from providers.tools import ToolCommand, ToolResult


class TlsModule(ProtocolModule):
    name = "tls"
    protocol = "tls"
    safety = SafetyClass.SAFE
    required_tool = "openssl"
    timeout_seconds = 20.0
    version_args = ("version",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({443, 636, 993, 995, 465, 990, 8443}),
            service_names=frozenset(
                {"https", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps"}
            ),
            tunnels=frozenset({"ssl", "tls"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.openssl_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        args = [
            "s_client",
            "-connect",
            connect_endpoint(target.address, target.port),
            "-servername",
            safe_hostname(target.hostname) or canonical_servername(target.address),
        ]
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
        return parse_openssl_sclient(result)


def canonical_servername(address: str) -> str:
    """OpenSSL -servername needs a token; use the literal IP when no hostname exists."""
    from protocol_audits.targets import canonical_host

    return canonical_host(address)
