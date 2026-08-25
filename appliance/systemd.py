"""Render systemd unit files without secrets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from appliance.paths import InstallPaths, SERVICE_USER, WIRESHARK_GROUP


SG_BINARY = Path("/usr/bin/sg")


def _exec_start(python: Path, module: str, *, user_session: bool) -> str:
    command = f"{python} -m {module}"
    if not user_session:
        return command
    # User systemd inherits groups from user@.service. SupplementaryGroups=
    # is not available in a user unit. If the account joined wireshark after
    # that manager started, dumpcap (0750 root:wireshark) is not executable
    # until logout. sg is setuid and rebuilds group membership from NSS.
    # Do not set ReadWritePaths= here: that mount namespace makes sg setgid
    # fail with EINVAL under systemd --user.
    return f'{SG_BINARY} {WIRESHARK_GROUP} -c "{command}"'


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
    hardening = ""
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
            f"ReadWritePaths={paths.data_dir} /etc/wirescope "
            "-/etc/network -/etc/NetworkManager -/etc/systemd/network\n"
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
ExecStart={_exec_start(python, "backend", user_session=user_session)}
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
    hardening = ""
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
ExecStart={_exec_start(python, "jobs.worker", user_session=user_session)}
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


def render_getty_autologin(user: str = SERVICE_USER) -> str:
    """Optional tty1 autologin drop-in used when the kiosk is not running."""

    return f"""[Service]
# Fallback console when the kiosk is disabled or not started.
# While the kiosk runs it Conflicts=getty@tty1.service and owns tty1.
ExecStart=
ExecStart=-/sbin/agetty --autologin {user} --noclear %I $TERM
"""


def render_kiosk_unit(paths: InstallPaths, *, user_session: bool = False) -> str:
    kiosk = paths.project_root / "packaging" / "kiosk" / "kiosk.sh"
    python = paths.python
    env_file = paths.env_file
    identity = ""
    session_env = ""
    tty = ""
    runtime = ""
    extra_env = ""
    conflicts = ""
    after = "wirescope-api.service"
    wanted = "graphical-session.target"
    if not user_session:
        identity = (
            f"User={paths.service_user}\n"
            f"Group={paths.service_group}\n"
            "SupplementaryGroups=video\n"
        )
        after = (
            "wirescope-api.service getty@tty1.service "
            "systemd-user-sessions.service"
        )
        wanted = "multi-user.target"
        # getty is only a fallback console when the kiosk is not running.
        # Do not use OnFailure=getty here: systemd enters failed state before
        # Restart=on-failure is processed, so OnFailure would race the kiosk
        # restart for tty1 and can cancel the restart transaction.
        conflicts = (
            "Conflicts=getty@tty1.service\n"
            "# OnFailure=getty@tty1.service is intentionally omitted: "
            "it races Restart=on-failure for tty1.\n"
        )
        tty = (
            "PAMName=login\n"
            "TTYPath=/dev/tty1\n"
            "TTYReset=yes\n"
            "TTYVHangup=yes\n"
            "TTYVTDisallocate=yes\n"
            "StandardInput=tty\n"
            "UtmpIdentifier=tty1\n"
            "UtmpMode=user\n"
        )
        runtime = (
            "RuntimeDirectory=wirescope-kiosk\n"
            "RuntimeDirectoryMode=0700\n"
        )
        extra_env = (
            f"Environment=HOME={paths.data_dir}\n"
            "Environment=XDG_RUNTIME_DIR=/run/wirescope-kiosk\n"
            "Environment=WLR_LIBSEAT_BACKEND=logind\n"
        )
    else:
        session_env = "PassEnvironment=DISPLAY WAYLAND_DISPLAY XAUTHORITY\n"
        after = "graphical-session.target wirescope-api.service"
    return f"""[Unit]
Description=WireScope local operator kiosk
Documentation=file://{paths.project_root}/docs/INSTALLATION.md
After={after}
Wants=wirescope-api.service
{conflicts}StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
{identity}WorkingDirectory={paths.project_root}
EnvironmentFile=-{env_file}
{extra_env}{session_env}Environment=WIRESCOPE_KIOSK_URL=http://127.0.0.1:8000/
{runtime}{tty}ExecStartPre={python} -m appliance wait-ready
ExecStart={kiosk}
Restart=on-failure
RestartPreventExitStatus=75
RestartSec=2
TimeoutStartSec=90
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wirescope-kiosk

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
