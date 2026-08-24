"""Unprivileged appliance network inventory and sudo-wrapped apply."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable

from appliance.netctl import (
    HELPER_PATH,
    ApplyResult,
    ApplySpec,
    Inventory,
    NetctlError,
    collect_inventory,
    evaluate_safety,
    gui_urls,
    inventory_to_dict,
    run_argv,
    session_interface_for,
    validate_spec,
)
from config.settings import Settings, get_settings


class NetworkConfirmRequired(NetctlError):
    def __init__(self, message: str, *, reasons: list[str], remaining_ipv4: list[str]):
        super().__init__(
            "confirm_required",
            message,
            details={"reasons": reasons, "remaining_ipv4": remaining_ipv4},
        )
        self.reasons = reasons
        self.remaining_ipv4 = remaining_ipv4


class NetworkService:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        runner: Callable[[list[str]], object] | None = None,
        which: Callable[[str], str | None] = shutil.which,
        use_sudo: bool = True,
        helper_path: Path | None = None,
        roles_path: Path | None = None,
        apply_fn: Callable[..., ApplyResult] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.runner = runner or run_argv
        self.which = which
        self.use_sudo = use_sudo
        self.helper_path = helper_path or Path(
            getattr(self.settings, "netctl_binary", str(HELPER_PATH))
        )
        self.roles_path = roles_path or Path("/etc/wirescope/network-roles.json")
        self.apply_fn = apply_fn

    def inventory(self) -> Inventory:
        return collect_inventory(
            self.runner,
            which=self.which,
            roles_path=self.roles_path,
        )

    def list_payload(self) -> dict[str, object]:
        inventory = self.inventory()
        payload = inventory_to_dict(inventory)
        payload["bind_host"] = self.settings.bind_host
        payload["bind_port"] = self.settings.bind_port
        payload["lan_bound"] = self.settings.bind_host not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
        payload["gui_urls"] = gui_urls(
            bind_host=self.settings.bind_host,
            bind_port=self.settings.bind_port,
            interfaces=inventory.interfaces,
            tls=self.settings.tls_enabled,
        )
        return payload

    def apply(
        self,
        spec: ApplySpec,
        *,
        client_host: str | None = None,
    ) -> dict[str, object]:
        spec = validate_spec(spec)
        spec.bind_host = self.settings.bind_host
        if not spec.session_interface:
            spec.session_interface = session_interface_for(
                client_host,
                self.runner,
            )
        inventory = self.inventory()
        safety = evaluate_safety(inventory, spec)
        if safety.needs_confirm:
            raise NetworkConfirmRequired(
                "This change needs confirmation: it may remove the last LAN IPv4 "
                "or the interface serving this GUI session",
                reasons=safety.reasons,
                remaining_ipv4=safety.remaining_ipv4,
            )
        if self.apply_fn is not None:
            result = self.apply_fn(spec)
        elif self.use_sudo:
            result = self._sudo_apply(spec)
        else:
            from appliance.netctl import apply_configuration

            result = apply_configuration(
                spec,
                self.runner,
                which=self.which,
                roles_path=self.roles_path,
                bind_port=self.settings.bind_port,
                tls=self.settings.tls_enabled,
            )
        payload = inventory_to_dict(result.inventory)
        payload["gui_urls"] = result.gui_urls
        payload["warnings"] = result.warnings
        payload["bind_host"] = self.settings.bind_host
        payload["bind_port"] = self.settings.bind_port
        return payload

    def _sudo_apply(self, spec: ApplySpec) -> ApplyResult:
        helper = self.which("sudo") or "/usr/bin/sudo"
        argv = [
            helper,
            "-n",
            str(self.helper_path),
            "apply",
            "--interface",
            spec.interface,
            "--role",
            spec.role,
            "--method",
            spec.method,
            "--bind-host",
            spec.bind_host,
            "--bind-port",
            str(self.settings.bind_port),
        ]
        if spec.address:
            argv.extend(["--address", spec.address])
        if spec.gateway:
            argv.extend(["--gateway", spec.gateway])
        for server in spec.dns:
            argv.extend(["--dns", server])
        if spec.confirm:
            argv.append("--confirm")
        if spec.session_interface:
            argv.extend(["--session-interface", spec.session_interface])
        completed = self.runner(argv)
        if getattr(completed, "returncode", 1) != 0:
            stderr = getattr(completed, "stderr", "") or ""
            stdout = getattr(completed, "stdout", "") or ""
            payload = _parse_error_json(stderr) or _parse_error_json(stdout)
            if payload and payload.get("error") == "confirm_required":
                details = payload.get("details") or {}
                raise NetworkConfirmRequired(
                    payload.get("message") or "Confirmation required",
                    reasons=list(details.get("reasons") or []),
                    remaining_ipv4=list(details.get("remaining_ipv4") or []),
                )
            if payload:
                raise NetctlError(
                    str(payload.get("error") or "netctl_failed"),
                    str(payload.get("message") or stderr or stdout or "netctl failed"),
                    details=payload.get("details") or {},
                )
            raise NetctlError(
                "netctl_failed",
                (stderr or stdout or "netctl failed").strip() or "netctl failed",
            )
        body = json.loads(getattr(completed, "stdout", "") or "{}")
        from appliance.netctl import NicSnapshot

        interfaces = [
            NicSnapshot(
                name=str(item["name"]),
                mac=item.get("mac"),
                state=item.get("state"),
                ipv4=list(item.get("ipv4") or []),
                ipv6=list(item.get("ipv6") or []),
                addressing=str(item.get("addressing") or "none"),
                has_default_route=bool(item.get("has_default_route")),
                role=str(item.get("role") or "unknown"),
                role_source=str(item.get("role_source") or "inferred"),
                is_loopback=bool(item.get("is_loopback")),
            )
            for item in body.get("interfaces") or []
        ]
        inventory = Inventory(
            interfaces=interfaces,
            backend=str(body.get("backend") or "unknown"),
            default_route_dev=body.get("default_route_dev"),
            dns=list(body.get("dns") or []),
        )
        return ApplyResult(
            inventory=inventory,
            gui_urls=list(body.get("gui_urls") or []),
            warnings=list(body.get("warnings") or []),
        )


def _parse_error_json(text: str) -> dict | None:
    text = (text or "").strip()
    if not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None
