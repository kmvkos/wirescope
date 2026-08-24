"""Declarative finding-rule registry independent of scanners."""

from findings.rules.dns import DnsRecursionRule, DnsVersionDisclosedRule
from findings.rules.http import (
    HttpServerDisclosureRule,
    MissingHstsRule,
    MissingSecurityHeadersRule,
)
from findings.rules.infrastructure import (
    LlmnrPresentRule,
    MultipleDhcpServersRule,
    NbnsPresentRule,
)
from findings.rules.ldap import LdapAnonymousBindRule
from findings.rules.management import InsecureManagementRule
from findings.rules.smb import (
    SmbLegacyDialectRule,
    SmbNullSessionRule,
    SmbSigningDisabledRule,
)
from findings.rules.snmp import SnmpUnauthenticatedRule
from findings.rules.ssh import WeakSshAlgorithmsRule
from findings.rules.tls import (
    LegacyTlsProtocolRule,
    TlsCertificateExpiredRule,
    TlsCertificateUntrustedRule,
    WeakTlsCipherRule,
)


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, object] = {}

    def register(self, rule: object) -> None:
        rule_id = getattr(rule, "id")
        if rule_id in self._rules:
            raise ValueError(f"Finding rule already registered: {rule_id}")
        self._rules[rule_id] = rule

    def get(self, rule_id: str) -> object:
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise LookupError(f"Unknown finding rule: {rule_id}") from exc

    @property
    def rules(self) -> tuple[object, ...]:
        return tuple(self._rules[key] for key in sorted(self._rules))

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._rules))


def default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    for rule in (
        WeakSshAlgorithmsRule(),
        LegacyTlsProtocolRule(),
        WeakTlsCipherRule(),
        TlsCertificateExpiredRule(),
        TlsCertificateUntrustedRule(),
        MissingHstsRule(),
        MissingSecurityHeadersRule(),
        HttpServerDisclosureRule(),
        SmbNullSessionRule(),
        SmbSigningDisabledRule(),
        SmbLegacyDialectRule(),
        DnsRecursionRule(),
        DnsVersionDisclosedRule(),
        SnmpUnauthenticatedRule(),
        LdapAnonymousBindRule(),
        InsecureManagementRule(),
        LlmnrPresentRule(),
        NbnsPresentRule(),
        MultipleDhcpServersRule(),
    ):
        registry.register(rule)
    return registry
