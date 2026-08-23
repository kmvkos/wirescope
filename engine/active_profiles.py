"""Typed active discovery profiles with bounded network impact."""

from pydantic import BaseModel, Field

from config.settings import Settings
from engine.scope import ActiveProfile


STANDARD_UDP_PORTS = (
    53,
    67,
    68,
    69,
    111,
    123,
    137,
    161,
    162,
    500,
    623,
    1900,
    4500,
    5353,
    5355,
)

DEEP_UDP_PORTS = tuple(
    sorted(
        {
            *STANDARD_UDP_PORTS,
            7,
            9,
            19,
            37,
            49,
            88,
            135,
            138,
            139,
            177,
            389,
            427,
            443,
            445,
            514,
            520,
            631,
            1434,
            1645,
            1646,
            1701,
            1812,
            1813,
            2049,
            3478,
            5060,
            5683,
            10000,
            17185,
            20031,
        }
    )
)


class ActiveScanProfile(BaseModel):
    name: ActiveProfile
    timing: str = Field(pattern=r"^T[0-4]$")
    tcp_top_ports: int | None = None
    tcp_ports: str | None = None
    udp_ports: tuple[int, ...] = ()
    service_detection: bool = False
    version_intensity: int | None = Field(default=None, ge=0, le=9)
    os_detection: bool = False
    run_tcp_scan: bool = True
    run_udp_scan: bool = False
    timeout_seconds: int = Field(gt=0)


def profile_for(
    profile: ActiveProfile,
    settings: Settings,
) -> ActiveScanProfile:
    if profile == ActiveProfile.DISCOVERY:
        return ActiveScanProfile(
            name=profile,
            timing="T3",
            tcp_top_ports=100,
            service_detection=False,
            os_detection=False,
            run_tcp_scan=False,
            run_udp_scan=False,
            timeout_seconds=settings.nmap_discovery_timeout_seconds,
        )
    if profile == ActiveProfile.STANDARD:
        return ActiveScanProfile(
            name=profile,
            timing="T3",
            tcp_top_ports=1_000,
            udp_ports=STANDARD_UDP_PORTS,
            service_detection=True,
            version_intensity=5,
            os_detection=True,
            run_tcp_scan=True,
            run_udp_scan=True,
            timeout_seconds=settings.nmap_standard_timeout_seconds,
        )
    return ActiveScanProfile(
        name=profile,
        timing="T3",
        tcp_ports="1-65535",
        udp_ports=DEEP_UDP_PORTS,
        service_detection=True,
        version_intensity=7,
        os_detection=True,
        run_tcp_scan=True,
        run_udp_scan=True,
        timeout_seconds=settings.nmap_deep_timeout_seconds,
    )
