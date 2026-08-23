"""Safe HTTP metadata collection via curl. Nikto/Nuclei are not enabled."""

from config.settings import Settings
from parsers.protocol.http import parse_curl_http
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import bracket_host
from providers.tools import ToolCommand, ToolResult


class HttpModule(ProtocolModule):
    name = "http"
    protocol = "http"
    safety = SafetyClass.SAFE
    required_tool = "curl"
    timeout_seconds = 15.0
    version_args = ("--version",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({80, 81, 8000, 8008, 8080, 8081, 8888, 3000, 443, 8443}),
            service_names=frozenset({"http", "http-proxy", "https", "http-alt"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.curl_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        scheme = "https" if _uses_tls(target) else "http"
        url = f"{scheme}://{bracket_host(target.address)}:{target.port}/"
        args = [
            "--silent",
            "--show-error",
            "--include",
            "--max-time",
            str(int(self.command_timeout(settings))),
            "--max-redirs",
            "0",
            "--max-filesize",
            "65536",
            "--path-as-is",
            "--user-agent",
            "WireScope/0.1",
        ]
        if scheme == "https":
            args.append("--insecure")
        args.append(url)
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=args,
                timeout_seconds=self.command_timeout(settings) + 2,
                environment={"LC_ALL": "C"},
            )
        ]

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        return parse_curl_http(result)


def _uses_tls(target: ProbeTarget) -> bool:
    if target.scheme_hint == "tls":
        return True
    name = (target.service.service_name or "").lower()
    tunnel = (target.service.tunnel or "").lower()
    return (
        target.port in {443, 8443}
        or name == "https"
        or tunnel in {"ssl", "tls"}
    )
