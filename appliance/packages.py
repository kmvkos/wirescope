"""Required base packages and selected optional providers.

Nuclei and Nikto are never selected by default. Absence of an optional
provider degrades capability, not installer success after the base set.
"""

from __future__ import annotations

from dataclasses import dataclass


FORBIDDEN_DEFAULT_PACKAGES = frozenset({"nuclei", "nikto", "nuclei-templates"})

REQUIRED_PACKAGES: tuple[str, ...] = (
    "python3",
    "python3-venv",
    "python3-pip",
    "python3-dev",
    "iproute2",
    "libcap2-bin",
    "ca-certificates",
    "sqlite3",
    "tshark",
    "wireshark-common",
    "adduser",
    "passwd",
)

# Optional protocol/discovery tools. Installed when --optional-providers is on
# (the default for a full appliance). Missing packages are skipped with a
# warning rather than failing the installer.
OPTIONAL_PROVIDERS: tuple[str, ...] = (
    "nmap",
    "openssl",
    "curl",
    "bind9-dnsutils",
    "smbclient",
    "snmp",
    "ldap-utils",
    "ssh-audit",
)

# Graphical kiosk stack for Raspberry Pi OS Lite. Not required to bring up the
# Debian VM appliance; the GUI is a browser client of the loopback API.
KIOSK_PACKAGES: tuple[str, ...] = (
    "xserver-xorg",
    "xinit",
    "openbox",
    "unclutter",
    "chromium",
)

KIOSK_PACKAGE_FALLBACKS: dict[str, tuple[str, ...]] = {
    "chromium": ("chromium-browser",),
}


@dataclass(frozen=True)
class PackageSelection:
    required: tuple[str, ...]
    optional: tuple[str, ...]
    kiosk: tuple[str, ...]

    @property
    def all_selected(self) -> tuple[str, ...]:
        seen: list[str] = []
        for name in (*self.required, *self.optional, *self.kiosk):
            if name not in seen:
                seen.append(name)
        return tuple(seen)


def select_packages(
    *,
    optional_providers: bool = True,
    kiosk: bool = False,
) -> PackageSelection:
    optional = OPTIONAL_PROVIDERS if optional_providers else ()
    kiosk_packages = KIOSK_PACKAGES if kiosk else ()
    selection = PackageSelection(
        required=REQUIRED_PACKAGES,
        optional=optional,
        kiosk=kiosk_packages,
    )
    forbidden = FORBIDDEN_DEFAULT_PACKAGES.intersection(selection.all_selected)
    if forbidden:
        raise ValueError(
            "installer must not select gated scanners: "
            + ", ".join(sorted(forbidden))
        )
    return selection
