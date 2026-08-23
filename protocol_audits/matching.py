"""Match inventory services to protocol-audit modules."""

from inventory.models import AssetRecord, ConfirmedScopeRecord, ServiceRecord
from protocol_audits.models import MatchedWork, SafetyClass
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.registry import ModuleRegistry
from protocol_audits.targets import build_probe_target, is_open_service


def match_work(
    *,
    registry: ModuleRegistry,
    assets: list[AssetRecord],
    services: list[ServiceRecord],
    scope: ConfirmedScopeRecord,
    allowed_modules: frozenset[str] | None = None,
) -> list[MatchedWork]:
    assets_by_id = {asset.id: asset for asset in assets}
    selected = [
        module
        for module in registry.default_modules()
        if allowed_modules is None or module.name in allowed_modules
    ]
    work: list[MatchedWork] = []
    for service in services:
        if not is_open_service(service):
            continue
        asset = assets_by_id.get(service.asset_id)
        if asset is None:
            continue
        target = build_probe_target(asset, service, scope)
        if target is None:
            continue
        for module in selected:
            if module.safety is SafetyClass.NEVER_DEFAULT:
                continue
            if module.matches(service):
                work.append(MatchedWork(module=module.name, target=target))
    return work


def matching_modules(
    registry: ModuleRegistry,
    service: ServiceRecord,
) -> list[ProtocolModule]:
    return [
        module
        for module in registry.default_modules()
        if module.safety is not SafetyClass.NEVER_DEFAULT
        and module.matches(service)
    ]
