"""Typed Nmap XML parser. Persistence stays outside this module."""

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, Field


class NmapParseCode(str, Enum):
    MALFORMED_XML = "malformed_xml"
    UNSUPPORTED_OUTPUT = "unsupported_output"
    INCOMPLETE_OUTPUT = "incomplete_output"


class NmapParseError(ValueError):
    def __init__(self, code: NmapParseCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class NmapHostname(BaseModel):
    name: str
    name_type: str = "PTR"


class NmapAddress(BaseModel):
    address: str
    family: str
    vendor: str | None = None


class NmapService(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    cpe: list[str] = Field(default_factory=list)
    banner: str | None = None


class NmapPort(BaseModel):
    protocol: str
    port: int
    state: str
    reason: str | None = None
    service: NmapService | None = None


class NmapOsMatch(BaseModel):
    name: str
    accuracy: int
    family: str | None = None
    generation: str | None = None
    vendor: str | None = None
    cpe: list[str] = Field(default_factory=list)


class NmapHost(BaseModel):
    status: str
    status_reason: str | None = None
    addresses: list[NmapAddress] = Field(default_factory=list)
    hostnames: list[NmapHostname] = Field(default_factory=list)
    ports: list[NmapPort] = Field(default_factory=list)
    os_matches: list[NmapOsMatch] = Field(default_factory=list)
    uptime_seconds: int | None = None
    network_distance: int | None = None

    @property
    def ipv4(self) -> str | None:
        return next(
            (
                item.address
                for item in self.addresses
                if item.family == "ipv4"
            ),
            None,
        )

    @property
    def ipv6(self) -> str | None:
        return next(
            (
                item.address
                for item in self.addresses
                if item.family == "ipv6"
            ),
            None,
        )

    @property
    def mac(self) -> str | None:
        return next(
            (
                item.address
                for item in self.addresses
                if item.family == "mac"
            ),
            None,
        )

    @property
    def mac_vendor(self) -> str | None:
        return next(
            (
                item.vendor
                for item in self.addresses
                if item.family == "mac" and item.vendor
            ),
            None,
        )


class NmapScanDocument(BaseModel):
    scanner: str
    args: str | None = None
    version: str | None = None
    xml_output_version: str | None = None
    start_time: datetime | None = None
    hosts: list[NmapHost] = Field(default_factory=list)
    hosts_up: int | None = None
    hosts_down: int | None = None
    hosts_total: int | None = None
    finished: bool = False


def parse_nmap_xml(source: str | Path | bytes) -> NmapScanDocument:
    if isinstance(source, Path):
        try:
            payload = source.read_bytes()
        except OSError as exc:
            raise NmapParseError(
                NmapParseCode.INCOMPLETE_OUTPUT,
                f"Could not read Nmap XML: {exc}",
            ) from exc
    elif isinstance(source, bytes):
        payload = source
    else:
        payload = source.encode("utf-8")

    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise NmapParseError(
            NmapParseCode.MALFORMED_XML,
            f"Nmap XML is malformed: {exc}",
        ) from exc

    if root.tag != "nmaprun":
        raise NmapParseError(
            NmapParseCode.UNSUPPORTED_OUTPUT,
            f"Unsupported Nmap XML root element: {root.tag}",
        )

    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    hosts_stats = runstats.find("hosts") if runstats is not None else None
    if runstats is None or finished is None:
        raise NmapParseError(
            NmapParseCode.INCOMPLETE_OUTPUT,
            "Nmap XML is missing runstats/finished",
        )

    return NmapScanDocument(
        scanner=root.attrib.get("scanner", "nmap"),
        args=root.attrib.get("args"),
        version=root.attrib.get("version"),
        xml_output_version=root.attrib.get("xmloutputversion"),
        start_time=_unix_time(root.attrib.get("start")),
        hosts=[_parse_host(host) for host in root.findall("host")],
        hosts_up=_optional_int(
            hosts_stats.attrib.get("up") if hosts_stats is not None else None
        ),
        hosts_down=_optional_int(
            hosts_stats.attrib.get("down") if hosts_stats is not None else None
        ),
        hosts_total=_optional_int(
            hosts_stats.attrib.get("total") if hosts_stats is not None else None
        ),
        finished=True,
    )


def live_targets(document: NmapScanDocument) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for host in document.hosts:
        if host.status != "up":
            continue
        for address in (host.ipv4, host.ipv6):
            if address and address not in seen:
                seen.add(address)
                targets.append(address)
    return targets


def _parse_host(element: ElementTree.Element) -> NmapHost:
    status = element.find("status")
    os_element = element.find("os")
    uptime = element.find("uptime")
    distance = element.find("distance")
    ports: list[NmapPort] = []
    for ports_element in element.findall("ports"):
        for port in ports_element.findall("port"):
            parsed = _parse_port(port)
            if parsed is not None:
                ports.append(parsed)
    return NmapHost(
        status=(
            status.attrib.get("state", "unknown")
            if status is not None
            else "unknown"
        ),
        status_reason=(
            status.attrib.get("reason") if status is not None else None
        ),
        addresses=[
            NmapAddress(
                address=item.attrib.get("addr", ""),
                family=item.attrib.get("addrtype", "unknown"),
                vendor=item.attrib.get("vendor"),
            )
            for item in element.findall("address")
            if item.attrib.get("addr")
        ],
        hostnames=[
            NmapHostname(
                name=item.attrib.get("name", ""),
                name_type=item.attrib.get("type", "PTR"),
            )
            for item in element.findall("./hostnames/hostname")
            if item.attrib.get("name")
        ],
        ports=ports,
        os_matches=_parse_os(os_element) if os_element is not None else [],
        uptime_seconds=_optional_int(
            uptime.attrib.get("seconds") if uptime is not None else None
        ),
        network_distance=_optional_int(
            distance.attrib.get("value") if distance is not None else None
        ),
    )


def _parse_port(element: ElementTree.Element) -> NmapPort | None:
    try:
        port = int(element.attrib.get("portid", ""))
    except ValueError:
        return None
    state = element.find("state")
    service = element.find("service")
    parsed_service = None
    if service is not None:
        parsed_service = NmapService(
            name=service.attrib.get("name"),
            product=service.attrib.get("product"),
            version=service.attrib.get("version"),
            extra_info=service.attrib.get("extrainfo"),
            tunnel=service.attrib.get("tunnel"),
            method=service.attrib.get("method"),
            confidence=_optional_int(service.attrib.get("conf")),
            cpe=[item.text for item in service.findall("cpe") if item.text],
            banner=service.attrib.get("servicefp"),
        )
    return NmapPort(
        protocol=element.attrib.get("protocol", "tcp"),
        port=port,
        state=(
            state.attrib.get("state", "unknown")
            if state is not None
            else "unknown"
        ),
        reason=state.attrib.get("reason") if state is not None else None,
        service=parsed_service,
    )


def _parse_os(element: ElementTree.Element) -> list[NmapOsMatch]:
    matches = []
    for osmatch in element.findall("osmatch"):
        osclass = osmatch.find("osclass")
        cpe = [item.text for item in osmatch.findall(".//cpe") if item.text]
        matches.append(
            NmapOsMatch(
                name=osmatch.attrib.get("name", "unknown"),
                accuracy=_optional_int(osmatch.attrib.get("accuracy")) or 0,
                family=(
                    osclass.attrib.get("osfamily")
                    if osclass is not None
                    else None
                ),
                generation=(
                    osclass.attrib.get("osgen")
                    if osclass is not None
                    else None
                ),
                vendor=(
                    osclass.attrib.get("vendor")
                    if osclass is not None
                    else None
                ),
                cpe=cpe,
            )
        )
    return matches


def _optional_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _unix_time(value: str | None) -> datetime | None:
    parsed = _optional_int(value)
    if parsed is None:
        return None
    return datetime.fromtimestamp(parsed, tz=timezone.utc)
