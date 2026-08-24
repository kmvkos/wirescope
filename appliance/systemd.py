"""Render systemd unit files without secrets."""

from __future__ import annotations

from dataclasses import dataclass

from appliance.paths import InstallPaths


SECRET_HINTS = (
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "BOOTSTRAP_AUDITOR_PASSWORD",
    "BOOTSTRAP_VIEWER_PASSWORD",
    "BEGIN PRIVATE",
)


@dataclass(frozen=True)
class UnitFile:
    name: str
    content: str


def _contains_secret(text: str) -> bool:
    upper = text.upper()
    return any(hint in upper for hint in SECRET_HINTS)


def render_api_unit(paths: InstallPaths, *, user_session: bool = False) -> str:
    python = paths.python
    env_file = paths.env_file
    identity = ""
    hardening = f"ReadWritePaths={paths.data_dir}\n"
    wanted = "default.target"
    if not user_session:
        identity = (
            f"User={paths.service_user}\n"
            f"Group={paths.service_group}\n"
            "SupplementaryGroups=wireshark\n"
        )
        hardening = (
            "NoNewPrivileges=true\n"
            "PrivateTmp=true\n"
            "ProtectHome=true\n"
            "ProtectSystem=full\n"
            f"ReadWritePaths={paths.data_dir}\n"
        )
        wanted = "multi-user.target"
    return f"""[Unit]
Description=WireScope application API
Documentation=file://{paths.project_root}/docs/INSTALLATION.md
After=network-online.target local-fs.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
{identity}WorkingDirectory={paths.project_root}
EnvironmentFile=-{env_file}
Environment=HOME={paths.data_dir}
ExecStart={python} -m backend
ExecStartPost={python} -m appliance wait-ready
Restart=on-failure
RestartSec=3
TimeoutStartSec=90
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wirescope-api
{hardening}
[Install]
WantedBy={wanted}
"""


def render_worker_unit(paths: InstallPaths, *, user_session: bool = False) -> str:
    python = paths.python
    env_file = paths.env_file
    identity = ""
    hardening = f"ReadWritePaths={paths.data_dir}\n"
    wanted = "default.target"
    if not user_session:
        identity = (
            f"User={paths.service_user}\n"
            f"Group={paths.service_group}\n"
            "SupplementaryGroups=wireshark\n"
        )
        hardening = (
            "PrivateTmp=true\n"
            "ProtectHome=true\n"
            "ProtectSystem=full\n"
            f"ReadWritePaths={paths.data_dir}\n"
        )
        wanted = "multi-user.target"
    return f"""[Unit]
Description=WireScope durable worker
Documentation=file://{paths.project_root}/docs/INSTALLATION.md
After=network-online.target local-fs.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
{identity}WorkingDirectory={paths.project_root}
EnvironmentFile=-{env_file}
Environment=HOME={paths.data_dir}
ExecStart={python} -m jobs.worker
Restart=on-failure
RestartSec=3
TimeoutStartSec=90
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wirescope-worker
{hardening}
[Install]
WantedBy={wanted}
"""


def render_kiosk_unit(paths: InstallPaths, *, user_session: bool = False) -> str:
    kiosk = paths.project_root / "packaging" / "kiosk" / "kiosk.sh"
    env_file = paths.env_file
    identity = ""
    wanted = "default.target"
    if not user_session:
        identity = (
            f"User={paths.service_user}\n"
            f"Group={paths.service_group}\n"
        )
        wanted = "graphical.target"
    return f"""[Unit]
Description=WireScope local kiosk browser
Documentation=file://{paths.project_root}/docs/INSTALLATION.md
After=wirescope-api.service
Wants=wirescope-api.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
{identity}WorkingDirectory={paths.project_root}
EnvironmentFile=-{env_file}
Environment=WIRESCOPE_KIOSK_URL=http://127.0.0.1:8000/
ExecStart={kiosk}
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wirescope-kiosk
PrivateTmp=true

[Install]
WantedBy={wanted}
"""


def render_journald_dropin() -> str:
    return """[Journal]
SystemMaxUse=256M
MaxRetentionSec=14day
"""


def unit_files(
    paths: InstallPaths,
    *,
    user_session: bool = False,
) -> tuple[UnitFile, ...]:
    files = (
        UnitFile(
            "wirescope-api.service",
            render_api_unit(paths, user_session=user_session),
        ),
        UnitFile(
            "wirescope-worker.service",
            render_worker_unit(paths, user_session=user_session),
        ),
        UnitFile(
            "wirescope-kiosk.service",
            render_kiosk_unit(paths, user_session=user_session),
        ),
    )
    for unit in files:
        if _contains_secret(unit.content):
            raise ValueError(f"refusing unit with secret material: {unit.name}")
        if "AmbientCapabilities=" in unit.content:
            raise ValueError(
                f"backend units must not set AmbientCapabilities: {unit.name}"
            )
        if "User=root" in unit.content:
            raise ValueError(f"backend units must not run as root: {unit.name}")
    return files
