"""Idempotent generic Linux appliance installation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import secrets
import sys

from appliance.bootstrap import password_from_host
from appliance.detect import Platform, UnsupportedPlatformError
from appliance.dumpcap import DumpcapReport, configure_dumpcap, inspect_dumpcap
from appliance.host import Host, HostError
from appliance.kiosk import (
    KIOSK_SCRIPT,
    KIOSK_SEAT_GROUPS,
    XINITRC,
    DisplayProbe,
    chromium_installed,
    kiosk_boot_note,
    kiosk_enable_reason,
    probe_display,
)
from appliance.packages import select_packages
from appliance.paths import ENV_FILE_MODE, InstallPaths, production_env_text
from appliance.systemd import (
    render_getty_autologin,
    render_journald_dropin,
    unit_files,
)
from appliance.tls import (
    PROXY_SAMPLE_NAMES,
    lan_warnings,
    proxy_sample_dir,
    validate_tls_settings,
)


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallConfig:
    paths: InstallPaths
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    apply_packages: bool = True
    optional_providers: bool = True
    install_kiosk: bool = False
    enable_kiosk: bool = False
    user_kiosk: bool = False
    display: DisplayProbe | None = None
    configure_journald: bool = True
    start_services: bool = True
    skip_pip: bool = False
    with_dev: bool = False
    overwrite_env: bool = False
    auditor_username: str = "auditor"
    auditor_password_file: Path | None = None
    viewer_username: str = "viewer"
    viewer_password_file: Path | None = None
    generate_admin_password: bool = False
    consume_password_files: bool = False
    dry_run: bool = False
    user_session: bool = False
    trust_proxy: bool = False
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    session_cookie_secure: bool | None = None


@dataclass
class InstallReport:
    platform: Platform
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dumpcap: DumpcapReport | None = None
    started: list[str] = field(default_factory=list)
    admin_created: list[str] = field(default_factory=list)
    admin_password_path: Path | None = None
    dry_run: bool = False


def service_environment(config: InstallConfig) -> dict[str, str]:
    paths = config.paths
    return {
        "WIRESCOPE_ROOT": str(paths.project_root),
        "WIRESCOPE_FRONTEND_DIR": str(paths.project_root / "frontend"),
        "WIRESCOPE_DATA_DIR": str(paths.data_dir),
        "WIRESCOPE_DATABASE_PATH": str(paths.database_path),
        "WIRESCOPE_EVIDENCE_DIR": str(paths.evidence_dir),
        "WIRESCOPE_RUNTIME_DIR": str(paths.runtime_dir),
        "WIRESCOPE_CAPTURE_DIR": str(paths.capture_dir),
        "WIRESCOPE_DOCS_ENABLED": "false",
        "WIRESCOPE_BIND_HOST": config.bind_host,
        "WIRESCOPE_BIND_PORT": str(config.bind_port),
        "WIRESCOPE_TRUST_PROXY": "true" if config.trust_proxy else "false",
        "HOME": str(paths.data_dir),
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def _exec_user(config: InstallConfig) -> str | None:
    if config.user_session:
        return None
    return config.paths.service_user


def _note(report: InstallReport, message: str) -> None:
    report.steps.append(message)


def install(config: InstallConfig, host: Host) -> InstallReport:
    if sys.version_info < (3, 11):
        raise InstallError("Python 3.11 or newer is required")
    try:
        platform = host.detect_platform()
    except UnsupportedPlatformError as exc:
        raise InstallError(str(exc)) from exc
    if not platform.supported:
        raise InstallError(
            f"unsupported platform {platform.distro_id}/{platform.arch}"
        )
    report = InstallReport(platform=platform, dry_run=config.dry_run)
    if config.dry_run:
        _plan(config, host, report)
        return report
    if host.geteuid() != 0 and not config.user_session:
        raise InstallError(
            "installer must run as root (sudo) for system units, "
            "or use --user-install on this account"
        )
    if config.user_session:
        report.warnings.append(
            "user-session install: skipped OS packages, dumpcap setcap, and system units"
        )
        if config.install_kiosk or config.user_kiosk:
            report.warnings.append(
                "user-session skipped kiosk packages; install chromium and "
                "cage or xinit with --with-kiosk as root, or the distro "
                "packages, then systemctl --user enable --now wirescope-kiosk"
            )
    _install_packages(config, host, report)
    _install_account(config, host, report)
    _install_directories(config, host, report)
    _install_env(config, host, report)
    _install_proxy_examples(config, host, report)
    _install_venv(config, host, report)
    report.dumpcap = _install_dumpcap(config, host, report)
    _install_units(config, host, report)
    _install_kiosk_files(config, host, report)
    _migrate(config, host, report)
    _bootstrap_admin(config, host, report)
    _start_services(config, host, report)
    return report


def _plan(config: InstallConfig, host: Host, report: InstallReport) -> None:
    selection = select_packages(
        family=report.platform.family,
        optional_providers=config.optional_providers,
        kiosk=config.install_kiosk,
    )
    _note(
        report,
        (
            f"detect {report.platform.pretty_name} {report.platform.arch} "
            f"({report.platform.family}/{report.platform.package_manager})"
        ),
    )
    _note(report, f"install packages: {', '.join(selection.all_selected)}")
    _note(report, f"ensure user {config.paths.service_user} (reuse if present)")
    _note(report, "configure dumpcap capabilities only")
    _note(report, f"write {config.paths.env_file} without secrets")
    _note(report, "install venv and pinned Python dependencies")
    _note(report, "install systemd units for api and worker")
    _note(report, "migrate SQLite and create initial auditor if needed")
    if config.start_services:
        _note(report, "enable and start wirescope-api and wirescope-worker")
    if config.install_kiosk:
        _note(
            report,
            "optional kiosk packages: cage or xinit plus Chromium "
            "(not a full desktop; boot kiosk on tty1)",
        )
    if config.enable_kiosk:
        _note(
            report,
            "system kiosk on tty1 after wirescope-api (cage or xinit + Chromium)",
        )
    if config.user_kiosk:
        _note(report, "user-session kiosk on 127.0.0.1:8000 after graphical login")
    if config.trust_proxy:
        _note(report, "LAN reverse proxy: API stays on loopback, cookie Secure")
    if config.tls_certfile and config.tls_keyfile:
        _note(report, "direct TLS cert/key paths in env (not in unit files)")
    report.warnings.extend(
        lan_warnings(
            bind_host=config.bind_host,
            trust_proxy=config.trust_proxy,
            tls_enabled=bool(config.tls_certfile and config.tls_keyfile),
        )
    )


def _install_packages(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    if not config.apply_packages or config.user_session:
        _note(report, "skip OS packages")
        return
    selection = select_packages(
        family=report.platform.family,
        optional_providers=config.optional_providers,
        kiosk=config.install_kiosk,
    )
    required_missing: list[str] = []
    for candidates in selection.required_groups:
        if any(host.package_installed(name) for name in candidates):
            continue
        chosen = _first_available(host, candidates)
        if chosen is None:
            raise InstallError(
                "required package unavailable: " + " / ".join(candidates)
            )
        required_missing.append(chosen)
    optional_names: list[str] = []
    for candidates in selection.optional_groups:
        if any(host.package_installed(name) for name in candidates):
            continue
        chosen = _first_available(host, candidates)
        if chosen is None:
            report.warnings.append(
                "optional package unavailable: " + " / ".join(candidates)
            )
        else:
            optional_names.append(chosen)
    kiosk_names: list[str] = []
    for candidates in selection.kiosk_groups:
        if any(host.package_installed(name) for name in candidates):
            continue
        chosen = _first_available(host, candidates)
        if chosen is None:
            report.warnings.append(
                "kiosk package unavailable: " + " / ".join(candidates)
            )
        else:
            kiosk_names.append(chosen)
    names = tuple(required_missing + optional_names + kiosk_names)
    if not names:
        _note(report, "OS packages already installed")
        return
    result = host.install_packages(names)
    if not result.ok:
        raise InstallError(
            f"{report.platform.package_manager} install failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )
    still_missing = [
        " / ".join(candidates)
        for candidates in selection.required_groups
        if not any(host.package_installed(name) for name in candidates)
    ]
    if still_missing:
        raise InstallError(
            "required packages missing after install: " + ", ".join(still_missing)
        )
    _note(report, "installed packages: " + ", ".join(names))


def _first_available(host: Host, candidates: tuple[str, ...]) -> str | None:
    for name in candidates:
        if host.package_available(name):
            return name
    return None


def _install_account(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    user = config.paths.service_user
    group = config.paths.service_group
    if config.user_session:
        if not host.user_exists(user):
            raise InstallError(f"service account {user} does not exist")
        _note(report, f"reused calling account {user}")
        return
    host.ensure_group(group)
    if host.user_exists(user):
        _note(report, f"reused existing service account {user}")
    else:
        host.create_system_user(user, home=config.paths.data_dir, group=group)
        _note(report, f"created system account {user}")
    host.add_user_to_group(user, "wireshark")
    if config.install_kiosk or config.enable_kiosk:
        for seat_group in KIOSK_SEAT_GROUPS:
            if host.group_exists(seat_group):
                host.add_user_to_group(user, seat_group)


def _install_directories(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    for spec in config.paths.directories():
        owner = config.paths.service_user if config.user_session else spec.owner
        group = config.paths.service_group if config.user_session else spec.group
        host.mkdir(spec.path, mode=spec.mode, owner=owner, group=group)
    _note(report, f"configured data directories under {config.paths.data_dir}")


def _install_dumpcap(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> DumpcapReport:
    if not host.is_file(config.paths.dumpcap_path):
        if config.user_session:
            report.warnings.append(f"dumpcap not found at {config.paths.dumpcap_path}")
            return inspect_dumpcap(
                host,
                dumpcap_path=config.paths.dumpcap_path,
                service_user=config.paths.service_user,
                venv_python=config.paths.python,
            )
        raise InstallError(f"dumpcap not found at {config.paths.dumpcap_path}")
    if config.user_session:
        inspected = inspect_dumpcap(
            host,
            dumpcap_path=config.paths.dumpcap_path,
            service_user=config.paths.service_user,
            venv_python=config.paths.python,
        )
        if not inspected.ok:
            report.warnings.append(
                "dumpcap least privilege is incomplete without root: "
                + ", ".join(inspected.issues)
            )
        _note(report, "verified dumpcap without changing capabilities")
        return inspected
    configured = configure_dumpcap(
        host,
        dumpcap_path=config.paths.dumpcap_path,
        service_user=config.paths.service_user,
        venv_python=config.paths.python,
    )
    _note(report, "configured dumpcap file capabilities; backend remains unprivileged")
    return configured


def _install_env(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    tls_cert = str(config.tls_certfile) if config.tls_certfile else ""
    tls_key = str(config.tls_keyfile) if config.tls_keyfile else ""
    try:
        validate_tls_settings(tls_cert, tls_key)
    except ValueError as exc:
        raise InstallError(str(exc)) from exc
    if tls_cert and not host.is_file(Path(tls_cert)):
        raise InstallError(f"TLS certificate is missing: {tls_cert}")
    if tls_key and not host.is_file(Path(tls_key)):
        raise InstallError(f"TLS private key is missing: {tls_key}")
    text = production_env_text(
        config.paths,
        bind_host=config.bind_host,
        bind_port=config.bind_port,
        trust_proxy=config.trust_proxy,
        tls_certfile=tls_cert,
        tls_keyfile=tls_key,
        session_cookie_secure=config.session_cookie_secure,
    )
    env_owner = "root" if not config.user_session else config.paths.service_user
    exists = host.exists(config.paths.env_file)
    host.write_file(
        config.paths.env_file,
        text,
        mode=ENV_FILE_MODE,
        owner=env_owner,
        group=config.paths.service_group,
        overwrite=config.overwrite_env or not exists,
    )
    if exists and not config.overwrite_env:
        _note(report, f"kept existing {config.paths.env_file}")
    else:
        _note(report, f"wrote {config.paths.env_file}")
    if config.trust_proxy:
        _note(report, "LAN reverse proxy: API stays on loopback, cookie Secure")
    report.warnings.extend(
        warning
        for warning in lan_warnings(
            bind_host=config.bind_host,
            trust_proxy=config.trust_proxy,
            tls_enabled=bool(tls_cert and tls_key),
        )
        if warning not in report.warnings
        )


def _install_proxy_examples(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    source = proxy_sample_dir(config.paths.project_root)
    dest = config.paths.etc_dir / "proxy"
    owner = "root" if not config.user_session else config.paths.service_user
    group = "root" if not config.user_session else config.paths.service_group
    host.mkdir(dest, mode=0o755, owner=owner, group=group)
    copied = 0
    for name in PROXY_SAMPLE_NAMES:
        src = source / name
        if not src.is_file():
            continue
        host.write_file(
            dest / name,
            src.read_text(encoding="utf-8"),
            mode=0o644,
            owner=owner,
            group=group,
        )
        copied += 1
    if copied:
        _note(report, f"wrote {copied} LAN proxy/firewall examples in {dest}")
    else:
        _note(report, "LAN proxy examples were not found in packaging/proxy")


def _install_venv(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    python = host.which("python3") or "python3"
    if not host.is_file(config.paths.python):
        result = host.run([python, "-m", "venv", str(config.paths.venv_dir)])
        if not result.ok:
            raise InstallError(
                f"venv creation failed: {result.stderr.strip() or result.stdout.strip()}"
            )
        _note(report, f"created {config.paths.venv_dir}")
    else:
        _note(report, f"reused {config.paths.venv_dir}")
    if config.skip_pip:
        _note(report, "skip pip")
        return
    pip = str(config.paths.pip)
    upgrade = host.run([pip, "install", "--upgrade", "pip"])
    if not upgrade.ok:
        raise InstallError(
            f"pip upgrade failed: {upgrade.stderr.strip() or upgrade.stdout.strip()}"
        )
    spec = str(config.paths.project_root)
    if config.with_dev:
        spec = f"{spec}[dev]"
    installed = host.run([pip, "install", "-e", spec])
    if not installed.ok:
        raise InstallError(
            f"pip install failed: {installed.stderr.strip() or installed.stdout.strip()}"
        )
    _note(report, "installed pinned Python dependencies")


def _install_units(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    for unit in unit_files(config.paths, user_session=config.user_session):
        host.write_file(
            config.paths.systemd_dir / unit.name,
            unit.content,
            mode=0o644,
            owner="root" if not config.user_session else config.paths.service_user,
            group="root" if not config.user_session else config.paths.service_group,
        )
    if config.configure_journald and not config.user_session:
        host.mkdir(
            config.paths.journald_dir,
            mode=0o755,
            owner="root",
            group="root",
        )
        host.write_file(
            config.paths.journald_dir / "40-wirescope.conf",
            render_journald_dropin(),
            mode=0o644,
            owner="root",
            group="root",
        )
        _note(report, "configured journald retention drop-in")
    _note(report, f"wrote systemd units in {config.paths.systemd_dir}")
    if config.user_session:
        _note(
            report,
            "user units exec via sg wireshark so dumpcap works without a new login",
        )


def _install_kiosk_files(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    kiosk_owner = "root" if not config.user_session else config.paths.service_user
    kiosk_group = "root" if not config.user_session else config.paths.service_group
    kiosk_dir = config.paths.project_root / "packaging" / "kiosk"
    host.mkdir(kiosk_dir, mode=0o755, owner=kiosk_owner, group=kiosk_group)
    host.write_file(
        kiosk_dir / "kiosk.sh",
        KIOSK_SCRIPT,
        mode=0o755,
        owner=kiosk_owner,
        group=kiosk_group,
    )
    host.write_file(
        kiosk_dir / "xinitrc",
        XINITRC,
        mode=0o755,
        owner=kiosk_owner,
        group=kiosk_group,
    )
    if not config.user_session and (config.install_kiosk or config.enable_kiosk):
        dropin_dir = config.paths.systemd_dir / "getty@tty1.service.d"
        host.mkdir(
            dropin_dir,
            mode=0o755,
            owner="root",
            group="root",
        )
        host.write_file(
            dropin_dir / "wirescope-autologin.conf",
            render_getty_autologin(config.paths.service_user),
            mode=0o644,
            owner="root",
            group="root",
        )
        _note(report, "wrote getty@tty1 autologin drop-in (kiosk Conflicts getty)")
    _note(
        report,
        "wrote local operator kiosk templates (tty1 boot kiosk, loopback GUI)",
    )


def _migrate(config: InstallConfig, host: Host, report: InstallReport) -> None:
    env = service_environment(config)
    result = host.run(
        [
            str(config.paths.alembic),
            "-c",
            str(config.paths.project_root / "alembic.ini"),
            "upgrade",
            "head",
        ],
        env={**env},
        cwd=config.paths.project_root,
        user=_exec_user(config),
    )
    if not result.ok:
        raise InstallError(
            "database migration failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )
    _note(report, "applied SQLite migrations")


def _bootstrap_admin(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    auditor_file = config.auditor_password_file
    viewer_file = config.viewer_password_file
    if config.generate_admin_password and auditor_file is None:
        generated = config.paths.etc_dir / "initial-admin.txt"
        if host.exists(generated):
            auditor_file = generated
            report.admin_password_path = generated
            _note(report, f"reused existing {generated}")
        else:
            password = secrets.token_urlsafe(24)
            host.write_file(
                generated,
                password + "\n",
                mode=0o600,
                owner="root" if not config.user_session else config.paths.service_user,
                group="root" if not config.user_session else config.paths.service_group,
            )
            auditor_file = generated
            report.admin_password_path = generated
            _note(
                report,
                f"generated initial auditor {config.auditor_username} password at {generated}",
            )
    if auditor_file is None:
        report.warnings.append(
            "no auditor password file; skipped initial admin creation"
        )
        return
    runtime_auditor = config.paths.bootstrap_dir / "auditor"
    password = password_from_host(host, auditor_file)
    host.write_file(
        runtime_auditor,
        password + "\n",
        mode=0o600,
        owner=config.paths.service_user,
        group=config.paths.service_group,
    )
    argv = [
        str(config.paths.python),
        "-m",
        "appliance",
        "bootstrap-admin",
        "--auditor-username",
        config.auditor_username,
        "--auditor-password-file",
        str(runtime_auditor),
    ]
    runtime_viewer: Path | None = None
    if viewer_file is not None:
        runtime_viewer = config.paths.bootstrap_dir / "viewer"
        viewer_password = password_from_host(host, viewer_file)
        host.write_file(
            runtime_viewer,
            viewer_password + "\n",
            mode=0o600,
            owner=config.paths.service_user,
            group=config.paths.service_group,
        )
        argv.extend(
            [
                "--viewer-username",
                config.viewer_username,
                "--viewer-password-file",
                str(runtime_viewer),
            ]
        )
    result = host.run(
        argv,
        env=service_environment(config),
        cwd=config.paths.project_root,
        user=_exec_user(config),
    )
    host.unlink(runtime_auditor)
    if runtime_viewer is not None:
        host.unlink(runtime_viewer)
    if config.consume_password_files:
        host.unlink(auditor_file)
        if viewer_file is not None:
            host.unlink(viewer_file)
    if not result.ok:
        raise InstallError(
            "initial admin creation failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )
    created = [
        item.strip()
        for item in result.stdout.splitlines()
        if item.strip() and not item.startswith("#")
    ]
    report.admin_created = created
    _note(report, "ensured initial local operator accounts")


def _start_services(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    if not config.start_services:
        _note(report, "skip service start")
        return
    if not host.systemctl_available():
        report.warnings.append(
            "systemd is not available; wrote unit files but did not start services"
        )
        return
    ctl = ["systemctl", "--user"] if config.user_session else ["systemctl"]
    reload_result = host.run([*ctl, "daemon-reload"])
    if not reload_result.ok:
        raise InstallError(
            "systemctl daemon-reload failed: "
            + (reload_result.stderr.strip() or reload_result.stdout.strip())
        )
    units = ["wirescope-api.service", "wirescope-worker.service"]
    enable = host.run([*ctl, "enable", "--now", *units])
    if not enable.ok:
        raise InstallError(
            "failed to enable WireScope services: "
            + (enable.stderr.strip() or enable.stdout.strip())
        )
    report.started.extend(units)
    _start_kiosk(config, host, report, ctl)
    _note(report, "started " + ", ".join(report.started))


def _start_kiosk(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
    ctl: list[str],
) -> None:
    want = config.enable_kiosk or config.user_kiosk
    if not want:
        return
    if config.user_kiosk and not config.user_session and not config.enable_kiosk:
        report.warnings.append(
            "system install: use --enable-kiosk for the tty1 boot kiosk. "
            "For a graphical login session use --user-install --user-kiosk"
        )
        return
    probe = config.display if config.display is not None else probe_display()
    blocked = kiosk_enable_reason(
        probe,
        chromium=chromium_installed(host.which),
        system_boot=not config.user_session,
    )
    if blocked:
        report.warnings.append(blocked)
        return
    if not config.user_session:
        note = kiosk_boot_note(probe)
        if note:
            report.warnings.append(note)
    kiosk_ctl = ["systemctl", "--user"] if config.user_session else ctl
    kiosk = host.run([*kiosk_ctl, "enable", "--now", "wirescope-kiosk.service"])
    if not kiosk.ok:
        report.warnings.append(
            "kiosk unit failed to start; API and worker are independent"
        )
        return
    report.started.append("wirescope-kiosk.service")


def verify_privileges(config: InstallConfig, host: Host) -> DumpcapReport:
    return inspect_dumpcap(
        host,
        dumpcap_path=config.paths.dumpcap_path,
        service_user=config.paths.service_user,
        venv_python=config.paths.python,
    )
