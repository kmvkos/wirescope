"""Idempotent Debian-family appliance installation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import secrets
import sys

from appliance.bootstrap import password_from_host
from appliance.detect import Platform, UnsupportedPlatformError
from appliance.dumpcap import DumpcapReport, configure_dumpcap, inspect_dumpcap
from appliance.host import Host, HostError
from appliance.kiosk import KIOSK_SCRIPT, XINITRC
from appliance.packages import KIOSK_PACKAGE_FALLBACKS, select_packages
from appliance.paths import ENV_FILE_MODE, InstallPaths, production_env_text
from appliance.systemd import render_journald_dropin, unit_files


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallConfig:
    paths: InstallPaths
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    apply_apt: bool = True
    optional_providers: bool = True
    install_kiosk: bool = False
    enable_kiosk: bool = False
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
            "installer must run as root, or use --user-install on this account"
        )
    if config.user_session:
        report.warnings.append(
            "user-session install: skipped apt, dumpcap setcap, and system units"
        )
    _install_packages(config, host, report)
    _install_account(config, host, report)
    _install_directories(config, host, report)
    _install_env(config, host, report)
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
        optional_providers=config.optional_providers,
        kiosk=config.install_kiosk,
    )
    _note(report, f"detect {report.platform.pretty_name} {report.platform.arch}")
    _note(report, f"install packages: {', '.join(selection.all_selected)}")
    _note(report, f"ensure user {config.paths.service_user} (reuse if present)")
    _note(report, "configure dumpcap capabilities only")
    _note(report, f"write {config.paths.env_file} without secrets")
    _note(report, "install venv and pinned Python dependencies")
    _note(report, "install systemd units for api and worker")
    _note(report, "migrate SQLite and create initial auditor if needed")
    if config.start_services:
        _note(report, "enable and start wirescope-api and wirescope-worker")
    if config.bind_host in {"0.0.0.0", "::"}:
        report.warnings.append(
            "bind_host is public; restrict with a firewall before exposing"
        )


def _install_packages(
    config: InstallConfig,
    host: Host,
    report: InstallReport,
) -> None:
    if not config.apply_apt or config.user_session:
        _note(report, "skip apt")
        return
    selection = select_packages(
        optional_providers=config.optional_providers,
        kiosk=config.install_kiosk,
    )
    required_missing = [
        name for name in selection.required if not host.package_installed(name)
    ]
    optional_names: list[str] = []
    for name in selection.optional:
        if host.package_installed(name):
            continue
        if host.package_available(name):
            optional_names.append(name)
        else:
            report.warnings.append(f"optional package unavailable: {name}")
    kiosk_names: list[str] = []
    for name in selection.kiosk:
        if host.package_installed(name):
            continue
        if host.package_available(name):
            kiosk_names.append(name)
            continue
        fallback_hit = False
        for fallback in KIOSK_PACKAGE_FALLBACKS.get(name, ()):
            if host.package_installed(fallback) or host.package_available(fallback):
                kiosk_names.append(fallback)
                fallback_hit = True
                break
        if not fallback_hit:
            report.warnings.append(f"kiosk package unavailable: {name}")
    names = tuple(required_missing + optional_names + kiosk_names)
    if not names:
        _note(report, "apt packages already installed")
        return
    result = host.install_packages(names)
    if not result.ok:
        raise InstallError(
            f"apt-get install failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    still_missing = [
        name for name in selection.required if not host.package_installed(name)
    ]
    if still_missing:
        raise InstallError(
            "required packages missing after apt: " + ", ".join(still_missing)
        )
    _note(report, "installed packages: " + ", ".join(names))


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
    text = production_env_text(
        config.paths,
        bind_host=config.bind_host,
        bind_port=config.bind_port,
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
    if config.bind_host in {"0.0.0.0", "::"}:
        report.warnings.append(
            "API bind address is public; see SECURITY_MODEL.md firewall guidance"
        )


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
    _note(report, "wrote optional kiosk templates")


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
    if config.enable_kiosk:
        kiosk = host.run(
            [*ctl, "enable", "--now", "wirescope-kiosk.service"]
        )
        if not kiosk.ok:
            report.warnings.append(
                "kiosk unit failed to start; API and worker are independent"
            )
        else:
            report.started.append("wirescope-kiosk.service")
    _note(report, "started " + ", ".join(report.started))


def verify_privileges(config: InstallConfig, host: Host) -> DumpcapReport:
    return inspect_dumpcap(
        host,
        dumpcap_path=config.paths.dumpcap_path,
        service_user=config.paths.service_user,
        venv_python=config.paths.python,
    )
