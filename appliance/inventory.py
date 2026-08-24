"""Dependency and OS-package inventory used by docs and release checksums."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from appliance.packages import packages_by_family, select_packages


@dataclass(frozen=True)
class FamilyPackages:
    family: str
    label: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    kiosk: tuple[str, ...]


@dataclass(frozen=True)
class DependencyInventory:
    python_requires: str
    python_runtime: tuple[str, ...]
    python_dev: tuple[str, ...]
    os_required: tuple[str, ...]
    os_optional: tuple[str, ...]
    os_kiosk: tuple[str, ...]
    families: tuple[FamilyPackages, ...]
    gated_not_installed: tuple[str, ...]


_FAMILY_LABELS = {
    "debian": "Debian / Ubuntu (apt)",
    "rhel": "Fedora / RHEL / Rocky (dnf or yum)",
    "suse": "openSUSE / SLES (zypper)",
}


def python_dependencies(project_root: Path) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    document = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = document["project"]
    runtime = tuple(project.get("dependencies", []))
    dev = tuple(project.get("optional-dependencies", {}).get("dev", []))
    requires = str(project.get("requires-python", ""))
    return runtime, dev, requires


def build_inventory(project_root: Path) -> DependencyInventory:
    runtime, dev, requires = python_dependencies(project_root)
    debian = select_packages(family="debian", optional_providers=True, kiosk=True)
    families = tuple(
        FamilyPackages(
            family=family,
            label=_FAMILY_LABELS[family],
            required=selection.required,
            optional=selection.optional,
            kiosk=selection.kiosk,
        )
        for family, selection in packages_by_family().items()
    )
    return DependencyInventory(
        python_requires=requires,
        python_runtime=runtime,
        python_dev=dev,
        os_required=debian.required,
        os_optional=debian.optional,
        os_kiosk=debian.kiosk,
        families=families,
        gated_not_installed=("nuclei", "nikto"),
    )


def render_inventory_text(inventory: DependencyInventory) -> str:
    def section(title: str, items: tuple[str, ...]) -> str:
        body = "\n".join(f"- {item}" for item in items) or "- (none)"
        return f"## {title}\n\n{body}\n"

    parts = [
        "# WireScope dependency inventory",
        "",
        f"Python: `{inventory.python_requires}`",
        "",
        section("Pinned Python runtime", inventory.python_runtime),
        section("Pinned Python development extras", inventory.python_dev),
    ]
    for family in inventory.families:
        parts.append(section(f"Required OS packages — {family.label}", family.required))
        parts.append(
            section(f"Optional providers — {family.label}", family.optional)
        )
    parts.append(
        section(
            "Optional kiosk stack (local display; not a full desktop)",
            inventory.os_kiosk,
        )
    )
    parts.append(
        section(
            "Gated scanners never installed by default",
            inventory.gated_not_installed,
        )
    )
    return "\n".join(parts)
