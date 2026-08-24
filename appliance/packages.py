"""Required base packages and selected optional providers.

Package names differ across apt, dnf/yum, and zypper. Nuclei and Nikto are
never selected by default. Absence of an optional provider degrades
capability, not installer success after the base set.

Kiosk packages are an optional local-display stack (Cage or xinit plus
Chromium, plus VMware Xorg drivers), not a full desktop. They are not
required on headless servers.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping

APT_LOCK_FRONTEND = "/var/lib/dpkg/lock-frontend"
APT_LOCK_WAIT_SECONDS = 180

APT_NONINTERACTIVE_OPTIONS: tuple[str, ...] = (
    "-y",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "-o",
    "DPkg::Lock::Timeout=180",
)


FORBIDDEN_DEFAULT_PACKAGES = frozenset({"nuclei", "nikto", "nuclei-templates"})

# role -> family -> candidate package names in preference order
_REQUIRED: dict[str, dict[str, tuple[str, ...]]] = {
    "python3": {
        "debian": ("python3",),
        "rhel": ("python3",),
        "suse": ("python3",),
    },
    "python3-venv": {
        "debian": ("python3-venv",),
        "rhel": ("python3",),
        "suse": ("python3-venv", "python311-venv", "python312-venv", "python3-virtualenv"),
    },
    "python3-pip": {
        "debian": ("python3-pip",),
        "rhel": ("python3-pip",),
        "suse": ("python3-pip",),
    },
    "python3-dev": {
        "debian": ("python3-dev",),
        "rhel": ("python3-devel",),
        "suse": ("python3-devel",),
    },
    "iproute": {
        "debian": ("iproute2",),
        "rhel": ("iproute",),
        "suse": ("iproute2",),
    },
    "libcap": {
        "debian": ("libcap2-bin",),
        "rhel": ("libcap",),
        "suse": ("libcap-progs",),
    },
    "ca-certificates": {
        "debian": ("ca-certificates",),
        "rhel": ("ca-certificates",),
        "suse": ("ca-certificates",),
    },
    "sqlite": {
        "debian": ("sqlite3",),
        "rhel": ("sqlite",),
        "suse": ("sqlite3",),
    },
    "tshark": {
        "debian": ("tshark",),
        "rhel": ("wireshark-cli",),
        "suse": ("wireshark-cli", "wireshark"),
    },
    "dumpcap": {
        "debian": ("wireshark-common",),
        "rhel": ("wireshark-cli",),
        "suse": ("wireshark-cli", "wireshark"),
    },
    "passwd": {
        "debian": ("passwd",),
        "rhel": ("shadow-utils",),
        "suse": ("shadow",),
    },
    "adduser": {
        "debian": ("adduser",),
        "rhel": ("shadow-utils",),
        "suse": ("shadow",),
    },
}

_OPTIONAL: dict[str, dict[str, tuple[str, ...]]] = {
    "nmap": {
        "debian": ("nmap",),
        "rhel": ("nmap",),
        "suse": ("nmap",),
    },
    "openssl": {
        "debian": ("openssl",),
        "rhel": ("openssl",),
        "suse": ("openssl",),
    },
    "curl": {
        "debian": ("curl",),
        "rhel": ("curl",),
        "suse": ("curl",),
    },
    "dnsutils": {
        "debian": ("bind9-dnsutils", "dnsutils"),
        "rhel": ("bind-utils",),
        "suse": ("bind-utils",),
    },
    "smbclient": {
        "debian": ("smbclient",),
        "rhel": ("samba-client",),
        "suse": ("samba-client",),
    },
    "snmp": {
        "debian": ("snmp",),
        "rhel": ("net-snmp-utils",),
        "suse": ("net-snmp",),
    },
    "ldap": {
        "debian": ("ldap-utils",),
        "rhel": ("openldap-clients",),
        "suse": ("openldap2-client",),
    },
    "ssh-audit": {
        "debian": ("ssh-audit",),
        "rhel": ("ssh-audit",),
        "suse": ("ssh-audit",),
    },
}

# Optional local operator console. Not a GNOME/XFCE/KDE desktop; skip if missing.
# VMware: Xorg + vmware driver. Elsewhere: Cage, else xinit + Chromium --kiosk.
_KIOSK: dict[str, dict[str, tuple[str, ...]]] = {
    "cage": {
        "debian": ("cage",),
        "rhel": ("cage",),
        "suse": ("cage",),
    },
    "xserver": {
        "debian": ("xserver-xorg",),
        "rhel": ("xorg-x11-server-Xorg",),
        "suse": ("xorg-x11-server",),
    },
    "xinit": {
        "debian": ("xinit",),
        "rhel": ("xorg-x11-xinit",),
        "suse": ("xinit",),
    },
    "openbox": {
        "debian": ("openbox",),
        "rhel": ("openbox",),
        "suse": ("openbox",),
    },
    "chromium": {
        "debian": ("chromium", "chromium-browser"),
        "rhel": ("chromium",),
        "suse": ("chromium",),
    },
    "xserver-video-vmware": {
        "debian": ("xserver-xorg-video-vmware",),
        "rhel": ("xorg-x11-drv-vmware",),
        "suse": ("xf86-video-vmware",),
    },
    "xserver-input": {
        "debian": ("xserver-xorg-input-all",),
        "rhel": ("xorg-x11-drivers",),
        "suse": ("xorg-x11-driver-input",),
    },
    "open-vm-tools": {
        "debian": ("open-vm-tools",),
        "rhel": ("open-vm-tools",),
        "suse": ("open-vm-tools",),
    },
}

KIOSK_PACKAGE_FALLBACKS: dict[str, tuple[str, ...]] = {
    "chromium": ("chromium-browser",),
}


def _groups_for(
    table: Mapping[str, Mapping[str, tuple[str, ...]]],
    family: str,
) -> tuple[tuple[str, ...], ...]:
    groups: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    for role_names in table.values():
        candidates = role_names.get(family) or role_names["debian"]
        if candidates not in seen:
            seen.add(candidates)
            groups.append(candidates)
    return tuple(groups)


def _first_names(groups: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    seen: list[str] = []
    for candidates in groups:
        name = candidates[0]
        if name not in seen:
            seen.append(name)
    return tuple(seen)


REQUIRED_PACKAGES: tuple[str, ...] = _first_names(_groups_for(_REQUIRED, "debian"))
OPTIONAL_PROVIDERS: tuple[str, ...] = _first_names(_groups_for(_OPTIONAL, "debian"))
KIOSK_PACKAGES: tuple[str, ...] = _first_names(_groups_for(_KIOSK, "debian"))


@dataclass(frozen=True)
class PackageSelection:
    required: tuple[str, ...]
    optional: tuple[str, ...]
    kiosk: tuple[str, ...]
    required_groups: tuple[tuple[str, ...], ...] = ()
    optional_groups: tuple[tuple[str, ...], ...] = ()
    kiosk_groups: tuple[tuple[str, ...], ...] = ()
    family: str = "debian"

    @property
    def all_selected(self) -> tuple[str, ...]:
        seen: list[str] = []
        for name in (*self.required, *self.optional, *self.kiosk):
            if name not in seen:
                seen.append(name)
        return tuple(seen)


def select_packages(
    *,
    family: str = "debian",
    optional_providers: bool = True,
    kiosk: bool = False,
) -> PackageSelection:
    required_groups = _groups_for(_REQUIRED, family)
    optional_groups = _groups_for(_OPTIONAL, family) if optional_providers else ()
    kiosk_groups = _groups_for(_KIOSK, family) if kiosk else ()
    selection = PackageSelection(
        required=_first_names(required_groups),
        optional=_first_names(optional_groups),
        kiosk=_first_names(kiosk_groups),
        required_groups=required_groups,
        optional_groups=optional_groups,
        kiosk_groups=kiosk_groups,
        family=family,
    )
    forbidden = FORBIDDEN_DEFAULT_PACKAGES.intersection(selection.all_selected)
    if forbidden:
        raise ValueError(
            "installer must not select gated scanners: "
            + ", ".join(sorted(forbidden))
        )
    return selection


def packages_by_family() -> dict[str, PackageSelection]:
    return {
        family: select_packages(family=family, optional_providers=True, kiosk=True)
        for family in ("debian", "rhel", "suse")
    }


def package_install_env(
    manager: str,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    env = dict(os.environ if environ is None else environ)
    if manager == "apt":
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
        env["APT_LISTCHANGES_FRONTEND"] = "none"
        env["NEEDRESTART_MODE"] = "l"
        env["NEEDRESTART_SUSPEND"] = "1"
    return env


def apt_lock_timeout_message(lock_path: str, holders: str) -> str:
    detail = holders.strip() or "(busy)"
    return (
        "установка ждет блокировку apt / install is waiting on an apt lock: "
        f"fuser {lock_path} → {detail}. "
        "Дождитесь завершения apt/unattended-upgrades и повторите."
    )


def package_install_argv(manager: str, names: tuple[str, ...]) -> list[str]:
    if manager == "apt":
        if not names:
            return ["apt-get"]
        return [
            "apt-get",
            *APT_NONINTERACTIVE_OPTIONS,
            "install",
            "--no-install-recommends",
            *names,
        ]
    if manager == "dnf":
        if not names:
            return ["dnf"]
        return ["dnf", "install", "-y", *names]
    if manager == "yum":
        if not names:
            return ["yum"]
        return ["yum", "install", "-y", *names]
    if manager == "zypper":
        if not names:
            return ["zypper"]
        return [
            "zypper",
            "--non-interactive",
            "install",
            "--auto-agree-with-licenses",
            *names,
        ]
    raise ValueError(f"unsupported package manager: {manager}")


def package_query_installed_argv(manager: str, name: str) -> list[str]:
    if manager == "apt":
        return ["dpkg-query", "-W", "-f", "${Status}", name]
    return ["rpm", "-q", name]


def package_query_available_argv(manager: str, name: str) -> list[str]:
    if manager == "apt":
        return ["apt-cache", "show", name]
    if manager == "dnf":
        return ["dnf", "list", "--quiet", name]
    if manager == "yum":
        return ["yum", "list", "-q", name]
    if manager == "zypper":
        return ["zypper", "--non-interactive", "search", "--match-exact", name]
    raise ValueError(f"unsupported package manager: {manager}")
