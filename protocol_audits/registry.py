"""Registry of protocol-audit modules.

Default modules are inventory-driven and safe. Gated stubs exist so optional
scanners can be named without being dispatched.
"""

from protocol_audits.modules.base import ProtocolModule
from protocol_audits.models import SafetyClass


GATED_MODULE_NAMES = frozenset({"testssl", "nikto", "nuclei"})


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, ProtocolModule] = {}
        self._gated: dict[str, ProtocolModule] = {}

    def register(self, module: ProtocolModule) -> None:
        if module.safety is SafetyClass.NEVER_DEFAULT:
            if module.name in self._gated or module.name in self._modules:
                raise ValueError(f"Module already registered: {module.name}")
            self._gated[module.name] = module
            return
        if module.name in self._modules or module.name in self._gated:
            raise ValueError(f"Module already registered: {module.name}")
        self._modules[module.name] = module

    def get(self, name: str) -> ProtocolModule:
        if name in self._modules:
            return self._modules[name]
        if name in self._gated:
            return self._gated[name]
        raise LookupError(f"Unknown protocol module: {name}")

    def default_modules(self) -> list[ProtocolModule]:
        return [self._modules[name] for name in sorted(self._modules)]

    @property
    def default_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._modules))

    @property
    def gated_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._gated))

    def is_gated(self, name: str) -> bool:
        return name in self._gated or name in GATED_MODULE_NAMES

    def known_names(self) -> frozenset[str]:
        return frozenset(self._modules) | frozenset(self._gated) | GATED_MODULE_NAMES


def default_registry() -> ModuleRegistry:
    from protocol_audits.modules.dns import DnsModule
    from protocol_audits.modules.gated import (
        NiktoModule,
        NucleiModule,
        TestsslModule,
    )
    from protocol_audits.modules.http import HttpModule
    from protocol_audits.modules.ldap import LdapModule
    from protocol_audits.modules.smb import SmbModule
    from protocol_audits.modules.snmp import SnmpModule
    from protocol_audits.modules.ssh import SshModule
    from protocol_audits.modules.tls import TlsModule

    registry = ModuleRegistry()
    for module in (
        SshModule(),
        TlsModule(),
        HttpModule(),
        DnsModule(),
        SmbModule(),
        SnmpModule(),
        LdapModule(),
        TestsslModule(),
        NiktoModule(),
        NucleiModule(),
    ):
        registry.register(module)
    return registry
