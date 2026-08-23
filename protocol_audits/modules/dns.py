"""In-scope DNS observations via dig. Does not query the public Internet."""

from config.settings import Settings
from parsers.protocol.dns import parse_dig
from protocol_audits.models import (
    ObservationDraft,
    ProbeTarget,
    SafetyClass,
    ServicePredicate,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.targets import canonical_host
from providers.tools import ToolCommand, ToolResult


class DnsModule(ProtocolModule):
    name = "dns"
    protocol = "dns"
    safety = SafetyClass.SAFE
    required_tool = "dig"
    timeout_seconds = 12.0
    version_args = ("-v",)
    parse_on_nonzero_exit = True
    predicates = (
        ServicePredicate(
            ports=frozenset({53}),
            protocols=frozenset({"udp"}),
            service_names=frozenset({"domain", "dns"}),
        ),
        ServicePredicate(
            ports=frozenset({53}),
            protocols=frozenset({"tcp"}),
            service_names=frozenset({"domain", "dns"}),
        ),
    )

    def tool_name(self, settings: Settings) -> str:
        return settings.dig_binary

    def build_commands(
        self,
        target: ProbeTarget,
        settings: Settings,
    ) -> list[ToolCommand]:
        host = canonical_host(target.address)
        timeout = max(1, int(self.command_timeout(settings) / 2))
        common = [
            f"@{host}",
            "+time=" + str(timeout),
            "+tries=1",
            "+norecurse",
            "+noall",
            "+answer",
            "+comments",
        ]
        if target.service.protocol.lower() == "tcp":
            common.append("+tcp")
        return [
            ToolCommand(
                tool=self.tool_name(settings),
                args=[*common, "version.bind", "CH", "TXT"],
                timeout_seconds=self.command_timeout(settings),
                environment={"LC_ALL": "C"},
            ),
            ToolCommand(
                tool=self.tool_name(settings),
                args=[*common, "id.server", "CH", "TXT"],
                timeout_seconds=self.command_timeout(settings),
                environment={"LC_ALL": "C"},
            ),
        ]

    def parse(
        self,
        result: ToolResult,
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        return parse_dig(result)

    def parse_results(
        self,
        results: list[ToolResult],
        target: ProbeTarget,
    ) -> list[ObservationDraft]:
        combined: list[ObservationDraft] = []
        seen: set[str] = set()
        for result in results:
            for draft in parse_dig(result):
                key = f"{draft.kind}:{draft.dedupe_key}"
                if key in seen and draft.kind != "dns_identity":
                    continue
                if draft.kind == "dns_identity":
                    existing = next(
                        (item for item in combined if item.kind == "dns_identity"),
                        None,
                    )
                    if existing is not None:
                        existing.data = {**existing.data, **{
                            key: value
                            for key, value in draft.data.items()
                            if value
                        }}
                        continue
                seen.add(key)
                combined.append(draft)
        return combined
