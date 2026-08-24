"""Command-line entry for appliance install, verify, backup, and bootstrap."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from appliance.backup import create_backup, restore_backup
from appliance.bootstrap import create_initial_operators, read_password_file
from appliance.detect import detect_platform
from appliance.dumpcap import inspect_dumpcap
from appliance.host import RealHost
from appliance.install import InstallConfig, install
from appliance.inventory import build_inventory, render_inventory_text
from appliance.paths import InstallPaths, discover_project_root
from appliance.release import checksum_paths, default_release_paths, render_checksums
from appliance.tls import self_signed_argv
from appliance.wait import wait_ready, health_url
from config.settings import get_settings


def _paths_from_args(args: argparse.Namespace) -> InstallPaths:
    project_root = Path(args.project_root).resolve()
    data_dir = Path(args.data_dir).resolve()
    etc_dir = Path(args.etc_dir).resolve()
    systemd_dir = Path(args.systemd_dir).resolve()
    venv_dir = Path(args.venv_dir).resolve() if args.venv_dir else project_root / ".venv"
    return InstallPaths(
        project_root=project_root,
        data_dir=data_dir,
        etc_dir=etc_dir,
        systemd_dir=systemd_dir,
        journald_dir=Path(args.journald_dir).resolve(),
        venv_dir=venv_dir,
        dumpcap_path=Path(args.dumpcap_path),
        service_user=args.service_user,
        service_group=args.service_group,
    )


def _add_path_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project-root",
        default=str(discover_project_root()),
        help="Git checkout (directory that contains packaging/). "
        "Recommended production layout: /opt/wirescope",
    )
    parser.add_argument("--data-dir", default="/var/lib/wirescope")
    parser.add_argument("--etc-dir", default="/etc/wirescope")
    parser.add_argument("--systemd-dir", default="/etc/systemd/system")
    parser.add_argument(
        "--journald-dir",
        default="/etc/systemd/journald.conf.d",
    )
    parser.add_argument("--venv-dir", default="")
    parser.add_argument("--dumpcap-path", default="/usr/bin/dumpcap")
    parser.add_argument("--service-user", default="wirescope")
    parser.add_argument("--service-group", default="wirescope")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wirescope-appliance")
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser(
        "detect",
        help="Show Linux family, package manager, and architecture",
    )
    detect.set_defaults(handler=cmd_detect)

    install_cmd = sub.add_parser("install", help="Install or upgrade the appliance")
    _add_path_arguments(install_cmd)
    install_cmd.add_argument("--bind-host", default="127.0.0.1")
    install_cmd.add_argument("--bind-port", type=int, default=8000)
    install_cmd.add_argument(
        "--trust-proxy",
        action="store_true",
        help="LAN reverse proxy: Secure cookies, trust X-Forwarded-* from loopback",
    )
    install_cmd.add_argument("--tls-cert", default="", help="Direct TLS certificate path")
    install_cmd.add_argument("--tls-key", default="", help="Direct TLS private key path")
    install_cmd.add_argument(
        "--skip-packages",
        action="store_true",
        help="Skip apt/dnf/zypper (enable kiosk without reinstalling packages)",
    )
    install_cmd.add_argument(
        "--skip-apt",
        action="store_true",
        help="alias for --skip-packages",
    )
    install_cmd.add_argument("--skip-pip", action="store_true")
    install_cmd.add_argument("--no-optional-providers", action="store_true")
    install_cmd.add_argument(
        "--with-kiosk",
        action="store_true",
        help="Install cage or xinit plus Chromium if missing (not a desktop; tty1 kiosk)",
    )
    install_cmd.add_argument(
        "--enable-kiosk",
        action="store_true",
        help="Enable the system kiosk on tty1 after boot (no desktop required)",
    )
    install_cmd.add_argument(
        "--user-kiosk",
        action="store_true",
        help="User-session kiosk after graphical login (loopback GUI, no LAN)",
    )
    install_cmd.add_argument("--no-journald", action="store_true")
    install_cmd.add_argument("--no-start", action="store_true")
    install_cmd.add_argument("--with-dev", action="store_true")
    install_cmd.add_argument("--overwrite-env", action="store_true")
    install_cmd.add_argument("--auditor-username", default="auditor")
    install_cmd.add_argument("--auditor-password-file", default="")
    install_cmd.add_argument("--viewer-username", default="viewer")
    install_cmd.add_argument("--viewer-password-file", default="")
    install_cmd.add_argument("--generate-admin-password", action="store_true")
    install_cmd.add_argument("--consume-password-files", action="store_true")
    install_cmd.add_argument("--dry-run", action="store_true")
    install_cmd.add_argument(
        "--user-install",
        action="store_true",
        help="Install user systemd units without root",
    )
    install_cmd.set_defaults(handler=cmd_install)

    verify = sub.add_parser("verify", help="Verify dumpcap least privilege")
    _add_path_arguments(verify)
    verify.set_defaults(handler=cmd_verify)

    bootstrap = sub.add_parser(
        "bootstrap-admin",
        help="Create the first auditor when the user table is empty",
    )
    bootstrap.add_argument("--auditor-username", default="auditor")
    bootstrap.add_argument("--auditor-password-file", required=True)
    bootstrap.add_argument("--viewer-username", default="viewer")
    bootstrap.add_argument("--viewer-password-file", default="")
    bootstrap.set_defaults(handler=cmd_bootstrap_admin)

    backup = sub.add_parser("backup", help="Write a SQLite/evidence backup")
    backup.add_argument("--backup-dir", default="")
    backup.add_argument("--no-evidence", action="store_true")
    backup.set_defaults(handler=cmd_backup)

    restore = sub.add_parser("restore", help="Restore a SQLite/evidence backup")
    restore.add_argument("archive")
    restore.add_argument("--no-evidence", action="store_true")
    restore.set_defaults(handler=cmd_restore)

    checksums = sub.add_parser("checksums", help="Write SHA-256 checksums")
    checksums.add_argument(
        "--project-root",
        default=str(discover_project_root()),
        help="Git checkout (directory that contains packaging/)",
    )
    checksums.add_argument("--output", default="")
    checksums.set_defaults(handler=cmd_checksums)

    inventory = sub.add_parser("inventory", help="Print dependency inventory")
    inventory.add_argument(
        "--project-root",
        default=str(discover_project_root()),
        help="Git checkout (directory that contains packaging/)",
    )
    inventory.set_defaults(handler=cmd_inventory)

    ready = sub.add_parser("wait-ready", help="Wait for /api/health")
    ready.add_argument("--url", default="")
    ready.add_argument("--timeout", type=float, default=60.0)
    ready.set_defaults(handler=cmd_wait_ready)

    tls_cmd = sub.add_parser(
        "tls-selfsigned",
        help="Write a lab self-signed TLS cert/key (not for untrusted networks)",
    )
    tls_cmd.add_argument("--output-dir", default="/etc/wirescope/tls")
    tls_cmd.add_argument("--common-name", default="wirescope.local")
    tls_cmd.add_argument("--days", type=int, default=825)
    tls_cmd.add_argument("--cert-name", default="cert.pem")
    tls_cmd.add_argument("--key-name", default="key.pem")
    tls_cmd.set_defaults(handler=cmd_tls_selfsigned)

    return parser


def cmd_detect(_args: argparse.Namespace) -> int:
    platform = detect_platform()
    print(f"family={platform.family}")
    print(f"package_manager={platform.package_manager}")
    print(f"id={platform.distro_id}")
    print(f"version={platform.version_id}")
    print(f"arch={platform.arch}")
    print(f"raspberry_pi={platform.raspberry_pi}")
    print(f"pretty={platform.pretty_name}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    if args.user_install:
        home = Path.home()
        if args.data_dir == "/var/lib/wirescope":
            args.data_dir = str(home / ".local/share/wirescope")
        if args.etc_dir == "/etc/wirescope":
            args.etc_dir = str(home / ".config/wirescope")
        if args.systemd_dir == "/etc/systemd/system":
            args.systemd_dir = str(home / ".config/systemd/user")
    config = InstallConfig(
        paths=_paths_from_args(args),
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        apply_packages=not args.skip_packages and not args.skip_apt and not args.user_install,
        optional_providers=not args.no_optional_providers,
        install_kiosk=args.with_kiosk or args.user_kiosk or args.enable_kiosk,
        enable_kiosk=args.enable_kiosk,
        user_kiosk=args.user_kiosk,
        configure_journald=not args.no_journald and not args.user_install,
        start_services=not args.no_start,
        skip_pip=args.skip_pip,
        with_dev=args.with_dev,
        overwrite_env=args.overwrite_env,
        auditor_username=args.auditor_username,
        auditor_password_file=(
            Path(args.auditor_password_file) if args.auditor_password_file else None
        ),
        viewer_username=args.viewer_username,
        viewer_password_file=(
            Path(args.viewer_password_file) if args.viewer_password_file else None
        ),
        generate_admin_password=args.generate_admin_password,
        consume_password_files=args.consume_password_files,
        dry_run=args.dry_run,
        user_session=args.user_install,
        trust_proxy=args.trust_proxy,
        tls_certfile=Path(args.tls_cert) if args.tls_cert else None,
        tls_keyfile=Path(args.tls_key) if args.tls_key else None,
    )
    report = install(config, RealHost())
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if report.admin_password_path:
        print(f"admin_password_file={report.admin_password_path}")
    if report.dumpcap is not None:
        print(f"dumpcap_ok={report.dumpcap.ok}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    paths = _paths_from_args(args)
    host = RealHost()
    report = inspect_dumpcap(
        host,
        dumpcap_path=paths.dumpcap_path,
        service_user=paths.service_user,
        venv_python=paths.python,
    )
    print(f"dumpcap={report.path}")
    print(f"owner={report.owner}:{report.group} mode={report.mode:04o}")
    print(f"capabilities={report.capabilities or 'none'}")
    print(f"setuid={report.setuid}")
    print(f"service_in_wireshark={report.service_in_wireshark}")
    print(f"ok={report.ok}")
    for issue in report.issues:
        print(f"issue={issue}")
    return 0 if report.ok else 1


def cmd_bootstrap_admin(args: argparse.Namespace) -> int:
    settings = get_settings()
    auditor = read_password_file(Path(args.auditor_password_file))
    viewer_password = ""
    if args.viewer_password_file:
        viewer_password = read_password_file(Path(args.viewer_password_file)).password
    created = create_initial_operators(
        settings,
        auditor_username=args.auditor_username,
        auditor_password=auditor.password,
        viewer_username=args.viewer_username if viewer_password else "",
        viewer_password=viewer_password,
    )
    if created:
        for username in created:
            print(username)
    else:
        print("# unchanged")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    settings = get_settings()
    backup_dir = (
        Path(args.backup_dir) if args.backup_dir else settings.data_dir / "backups"
    )
    archive = create_backup(
        database_path=settings.database_path,
        evidence_dir=settings.evidence_dir,
        backup_dir=backup_dir,
        include_evidence=not args.no_evidence,
    )
    print(archive.directory)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    settings = get_settings()
    restore_backup(
        Path(args.archive),
        database_path=settings.database_path,
        evidence_dir=settings.evidence_dir,
        restore_evidence=not args.no_evidence,
    )
    print("restored")
    return 0


def cmd_checksums(args: argparse.Namespace) -> int:
    root = Path(args.project_root).resolve()
    records = checksum_paths(default_release_paths(root), root=root)
    text = render_checksums(records)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(output)
    else:
        sys.stdout.write(text)
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    root = Path(args.project_root).resolve()
    sys.stdout.write(render_inventory_text(build_inventory(root)))
    return 0


def cmd_wait_ready(args: argparse.Namespace) -> int:
    wait_ready(url=args.url or health_url(), timeout_seconds=args.timeout)
    return 0


def cmd_tls_selfsigned(args: argparse.Namespace) -> int:
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    cert = output / args.cert_name
    key = output / args.key_name
    argv = self_signed_argv(
        certfile=cert,
        keyfile=key,
        common_name=args.common_name,
        days=args.days,
    )
    result = RealHost().run(argv)
    if not result.ok:
        print(result.stderr.strip() or result.stdout.strip(), file=sys.stderr)
        return 1
    cert.chmod(0o644)
    key.chmod(0o600)
    print(cert)
    print(key)
    return 0


def main(argv: list[str] | None = None) -> None:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        raise SystemExit(args.handler(args))
    except KeyboardInterrupt:
        print("установка прервана / install interrupted", file=sys.stderr)
        raise SystemExit(130)
