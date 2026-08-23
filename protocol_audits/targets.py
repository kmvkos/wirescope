"""In-scope inventory addresses used as protocol-audit targets."""

import ipaddress
import re

from inventory.models import AssetRecord, ConfirmedScopeRecord, ServiceRecord
from protocol_audits.models import ProbeTarget


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
OPEN_STATES = frozenset({"open", "open|filtered"})


def canonical_host(address: str) -> str:
    return str(ipaddress.ip_address(address.strip()))


def bracket_host(address: str) -> str:
    parsed = ipaddress.ip_address(canonical_host(address))
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


def connect_endpoint(address: str, port: int) -> str:
    if not 0 <= port <= 65_535:
        raise ValueError("port is out of range")
    return f"{bracket_host(address)}:{port}"


def safe_hostname(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().rstrip(".")
    if not candidate or candidate.startswith("-"):
        return None
    if any(char in candidate for char in {"/", "\\", " ", "\t", "\n", ":"}):
        return None
    if not _HOSTNAME_RE.fullmatch(candidate):
        return None
    return candidate


def address_in_scope(address: str, scope: ConfirmedScopeRecord) -> bool:
    parsed = ipaddress.ip_address(canonical_host(address))
    for target in scope.targets:
        network = ipaddress.ip_network(target, strict=False)
        if parsed.version == network.version and parsed in network:
            return True
    return False


def select_probe_address(
    asset: AssetRecord,
    scope: ConfirmedScopeRecord,
) -> str | None:
    in_scope = [
        address.address
        for address in asset.addresses
        if address_in_scope(address.address, scope)
    ]
    if not in_scope:
        return None
    ipv4 = [item for item in in_scope if ":" not in item]
    preferred = ipv4 or in_scope
    for address in asset.addresses:
        if address.is_primary and address.address in preferred:
            return canonical_host(address.address)
    return canonical_host(preferred[0])


def select_hostname(asset: AssetRecord) -> str | None:
    ranked = sorted(
        asset.names,
        key=lambda item: (
            0 if item.name_type.lower() == "ptr" else 1,
            item.source,
            item.name,
        ),
    )
    for record in ranked:
        hostname = safe_hostname(record.name)
        if hostname is not None:
            return hostname
    return None


def is_open_service(service: ServiceRecord) -> bool:
    return service.state.lower() in OPEN_STATES


def build_probe_target(
    asset: AssetRecord,
    service: ServiceRecord,
    scope: ConfirmedScopeRecord,
) -> ProbeTarget | None:
    if not is_open_service(service):
        return None
    address = select_probe_address(asset, scope)
    if address is None:
        return None
    return ProbeTarget(
        asset=asset,
        service=service,
        address=address,
        port=service.port,
        hostname=select_hostname(asset),
        scheme_hint=_scheme_hint(service),
    )


def _scheme_hint(service: ServiceRecord) -> str | None:
    name = (service.service_name or "").lower()
    tunnel = (service.tunnel or "").lower()
    if (
        service.port in {443, 8443, 636, 993, 995, 465, 990}
        or name in {"https", "ssl", "tls", "ldaps", "imaps", "pop3s", "smtps"}
        or tunnel in {"ssl", "tls"}
    ):
        return "tls"
    if service.port in {80, 8000, 8008, 8080, 8888} or name in {
        "http",
        "http-proxy",
    }:
        return "http"
    return None
