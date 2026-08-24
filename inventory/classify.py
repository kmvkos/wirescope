"""Cautious multi-signal device-class hints. These are not findings."""

from engine.passive_models import ConfidenceLevel
from inventory.models import DeviceClassHint


PRINTER_PORTS = {515, 631, 9100}
PRINTER_VENDORS = {
    "hewlett packard",
    "hp inc",
    "xerox",
    "brother",
    "canon",
    "epson",
    "lexmark",
    "kyocera",
    "ricoh",
}
NETWORK_VENDORS = {
    "cisco",
    "juniper",
    "mikrotik",
    "aruba",
    "ubiquiti",
    "fortinet",
    "palo alto",
    "netgear",
    "tp-link",
    "huawei",
    "zyxel",
    "extreme networks",
    "arista",
}
IOT_VENDORS = {
    "espressif",
    "tuya",
    "sonoff",
    "shelly",
    "hikvision",
    "dahua",
    "axis communications",
    "ring",
    "nest",
}
WINDOWS_PORTS = {135, 139, 445, 3389, 5355, 5357}
SERVER_PORTS = {22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443}
NETWORK_HINT_PORTS = {22, 23, 80, 161, 443, 8291}


def _confidence(sources: list[str], *, strong: bool = False) -> ConfidenceLevel:
    unique = len(set(sources))
    if strong and unique >= 2:
        return ConfidenceLevel.HIGH
    if unique >= 2:
        return ConfidenceLevel.MEDIUM
    if unique == 1:
        return ConfidenceLevel.MEDIUM if strong else ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


def classify_device(
    *,
    os_family: str | None,
    os_name: str | None,
    vendor: str | None,
    open_ports: set[tuple[str, int]],
    name_sources: set[str],
    passive_neighbors: bool = False,
) -> tuple[DeviceClassHint, ConfidenceLevel, list[str]]:
    vendor_l = (vendor or "").lower()
    os_blob = " ".join(part.lower() for part in (os_family, os_name) if part)
    tcp_ports = {port for protocol, port in open_ports if protocol == "tcp"}
    udp_ports = {port for protocol, port in open_ports if protocol == "udp"}

    sources: list[str] = []
    printer_vendor = any(token in vendor_l for token in PRINTER_VENDORS)
    printer_port = bool(tcp_ports & PRINTER_PORTS)
    printer_os = "printer" in os_blob
    if printer_vendor or printer_port or printer_os:
        if printer_vendor:
            sources.append("mac-vendor")
        if printer_port:
            sources.append("printer-port")
        if printer_os:
            sources.append("os-hint")
        return DeviceClassHint.PRINTER, _confidence(sources, strong=True), sources

    network_vendor = any(token in vendor_l for token in NETWORK_VENDORS)
    network_os = any(token in os_blob for token in ("router", "switch", "ios", "routeros", "junos"))
    network_ports = 161 in udp_ports and bool(tcp_ports & NETWORK_HINT_PORTS)
    if passive_neighbors or network_vendor or network_os or network_ports:
        if passive_neighbors:
            sources.append("lldp-or-cdp")
        if network_vendor:
            sources.append("mac-vendor")
        if network_os:
            sources.append("os-hint")
        if network_ports:
            sources.append("network-management-ports")
        return DeviceClassHint.NETWORK_DEVICE, _confidence(sources, strong=True), sources

    windows_os = "windows" in os_blob
    windows_ports = len(tcp_ports & WINDOWS_PORTS) >= 2
    windows_names = bool(name_sources & {"llmnr", "nbns"})
    if windows_os or windows_ports:
        if windows_os:
            sources.append("os-hint")
        if windows_ports:
            sources.append("windows-ports")
        if windows_names:
            sources.append("llmnr-or-nbns")
        return DeviceClassHint.WORKSTATION, _confidence(sources, strong=windows_os), sources

    server_port_count = len(tcp_ports & SERVER_PORTS)
    linux_os = "linux" in os_blob or "unix" in os_blob
    if server_port_count >= 2 or linux_os:
        if linux_os:
            sources.append("os-hint")
        if server_port_count >= 2:
            sources.append("server-ports")
        return DeviceClassHint.SERVER, _confidence(sources, strong=server_port_count >= 3), sources

    iot_vendor = any(token in vendor_l for token in IOT_VENDORS)
    mdns_limited = (
        "mdns" in name_sources
        and len(tcp_ports) <= 3
        and not (tcp_ports & (SERVER_PORTS - {80, 443}))
    )
    if iot_vendor or mdns_limited:
        if iot_vendor:
            sources.append("mac-vendor")
        if mdns_limited:
            sources.append("mdns-limited-ports")
        return DeviceClassHint.IOT, _confidence(sources, strong=iot_vendor and mdns_limited), sources

    return DeviceClassHint.UNKNOWN, ConfidenceLevel.UNKNOWN, []
