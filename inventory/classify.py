"""Cautious device-class hints. These are not security findings."""

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
}
WINDOWS_PORTS = {135, 139, 445, 3389, 5355, 5357}
SERVER_PORTS = {22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443}


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
    os_blob = " ".join(
        part.lower()
        for part in (os_family, os_name)
        if part
    )
    tcp_ports = {port for protocol, port in open_ports if protocol == "tcp"}
    sources: list[str] = []

    if (
        tcp_ports & PRINTER_PORTS
        or any(token in vendor_l for token in PRINTER_VENDORS)
        or "printer" in os_blob
    ):
        if tcp_ports & PRINTER_PORTS:
            sources.append("printer-port")
        if vendor_l:
            sources.append("mac-vendor")
        return (
            DeviceClassHint.PRINTER,
            ConfidenceLevel.MEDIUM if sources else ConfidenceLevel.LOW,
            sources or ["heuristic"],
        )

    if (
        passive_neighbors
        or any(token in vendor_l for token in NETWORK_VENDORS)
        or "router" in os_blob
        or "switch" in os_blob
        or "ios" in os_blob
    ):
        if passive_neighbors:
            sources.append("lldp-or-cdp")
        if vendor_l:
            sources.append("mac-vendor")
        if "router" in os_blob or "switch" in os_blob or "ios" in os_blob:
            sources.append("os-hint")
        return (
            DeviceClassHint.NETWORK_DEVICE,
            ConfidenceLevel.MEDIUM if len(sources) > 1 else ConfidenceLevel.LOW,
            sources or ["heuristic"],
        )

    if (
        "windows" in os_blob
        or "microsoft" in vendor_l
        or (tcp_ports & WINDOWS_PORTS and "llmnr" in name_sources)
    ):
        sources.append("os-hint" if "windows" in os_blob else "windows-ports")
        return DeviceClassHint.WORKSTATION, ConfidenceLevel.MEDIUM, sources

    if len(tcp_ports & SERVER_PORTS) >= 2 or "linux" in os_blob:
        if "linux" in os_blob:
            sources.append("os-hint")
        if tcp_ports & SERVER_PORTS:
            sources.append("server-ports")
        confidence = (
            ConfidenceLevel.MEDIUM
            if len(tcp_ports & SERVER_PORTS) >= 2
            else ConfidenceLevel.LOW
        )
        return DeviceClassHint.SERVER, confidence, sources or ["heuristic"]

    if (
        "mdns" in name_sources
        and len(tcp_ports) <= 3
        and not (tcp_ports & SERVER_PORTS - {80, 443})
    ):
        return (
            DeviceClassHint.IOT,
            ConfidenceLevel.LOW,
            ["mdns-limited-ports"],
        )

    return DeviceClassHint.UNKNOWN, ConfidenceLevel.UNKNOWN, []
