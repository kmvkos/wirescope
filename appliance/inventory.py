"""Dependency and OS-package inventory used by docs and release checksums."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from appliance.packages import (
    KIOSK_PACKAGES,
    OPTIONAL_PROVIDERS,
    REQUIRED_PACKAGES,
)


@dataclass(frozen=True)
class DependencyInventory:
    python_requires: str
    python_runtime: tuple[str, ...]
    python_dev: tuple[str, ...]
    os_required: tuple[str, ...]
    os_optional: tuple[str, ...]
    os_kiosk: tuple[str, ...]
    gated_not_installed: tuple[str, ...]


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
    return DependencyInventory(
        python_requires=requires,
        python_runtime=runtime,
        python_dev=dev,
        os_required=REQUIRED_PACKAGES,
        os_optional=OPTIONAL_PROVIDERS,
        os_kiosk=KIOSK_PACKAGES,
        gated_not_installed=("nuclei", "nikto"),
    )


def render_inventory_text(inventory: DependencyInventory) -> str:
    def section(title: str, items: tuple[str, ...]) -> str:
        body = "\n".join(f"- {item}" for item in items) or "- (none)"
        return f"## {title}\n\n{body}\n"

    return "\n".join(
        [
            "# WireScope dependency inventory",
            "",
            f"Python: `{inventory.python_requires}`",
            "",
            section("Pinned Python runtime", inventory.python_runtime),
            section("Pinned Python development extras", inventory.python_dev),
            section("Required OS packages (Debian / Raspberry Pi OS)", inventory.os_required),
            section("Optional providers (not Nuclei/Nikto)", inventory.os_optional),
            section("Optional kiosk stack", inventory.os_kiosk),
            section("Gated scanners never installed by default", inventory.gated_not_installed),
        ]
    )
