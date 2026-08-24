from pathlib import Path

from appliance.host import (
    MemoryFile,
    MemoryHost,
    debian_amd64_platform,
    fedora_amd64_platform,
    opensuse_amd64_platform,
)
from appliance.install import InstallConfig, InstallError, install
from appliance.packages import REQUIRED_PACKAGES
from appliance.paths import InstallPaths


def _host() -> MemoryHost:
    host = MemoryHost(platform=debian_amd64_platform())
    host.files["/usr/bin/dumpcap"] = MemoryFile(
        content="",
        mode=0o755,
        owner="nobody",
        group="nogroup",
    )
    host.packages.update(REQUIRED_PACKAGES)
    host.packages.update({"nmap", "openssl", "curl"})
    return host


def _config(tmp_path: Path, **overrides) -> InstallConfig:
    paths = InstallPaths(
        project_root=Path("/opt/wirescope"),
        data_dir=tmp_path / "var",
        etc_dir=tmp_path / "etc",
        systemd_dir=tmp_path / "systemd",
        journald_dir=tmp_path / "journald",
        venv_dir=tmp_path / "venv",
        dumpcap_path=Path("/usr/bin/dumpcap"),
        service_user="wirescope",
        service_group="wirescope",
    )
    values = dict(
        paths=paths,
        apply_packages=True,
        optional_providers=True,
        install_kiosk=False,
        start_services=True,
        skip_pip=False,
        generate_admin_password=True,
        dry_run=False,
    )
    values.update(overrides)
    return InstallConfig(**values)


def test_install_reuses_account_and_is_idempotent(tmp_path):
    host = _host()
    host.users["wirescope"] = "wirescope"
    host.groups["wirescope"] = {"wirescope"}
    host.groups["wireshark"] = {"wirescope"}
    config = _config(tmp_path)
    first = install(config, host)
    useradds = [item for item in host.commands if item and item[0] == "useradd"]
    first_commands = list(host.commands)
    second = install(config, host)
    assert first.dumpcap is not None and first.dumpcap.ok
    assert second.dumpcap is not None and second.dumpcap.ok
    assert useradds == []
    assert [item for item in host.commands if item and item[0] == "useradd"] == []
    assert host.file_mode(config.paths.env_file) == 0o640
    assert "PASSWORD" not in host.read_text(config.paths.env_file)
    api_unit = host.read_text(config.paths.systemd_dir / "wirescope-api.service")
    assert "User=wirescope" in api_unit
    assert "AmbientCapabilities=" not in api_unit
    assert first.admin_created == ["auditor"]
    nuclei = [item for item in host.commands if "nuclei" in item or "nikto" in item]
    assert nuclei == []
    assert len(host.commands) >= len(first_commands)
    kiosk_enabled = [
        item
        for item in host.commands
        if item[:3] == ("systemctl", "enable", "--now")
        and "wirescope-kiosk.service" in item
    ]
    assert kiosk_enabled == []


def test_install_creates_system_user_when_missing(tmp_path):
    host = _host()
    config = _config(tmp_path, start_services=False, apply_packages=False)
    report = install(config, host)
    assert host.user_exists("wirescope")
    assert ("useradd", "wirescope") in host.commands
    assert report.dumpcap.ok


def test_install_dry_run_does_not_write_units(tmp_path):
    host = _host()
    config = _config(tmp_path, dry_run=True)
    report = install(config, host)
    assert report.dry_run is True
    assert not host.exists(config.paths.systemd_dir / "wirescope-api.service")
    assert any("systemd" in step for step in report.steps)


def test_user_install_writes_user_units(tmp_path):
    host = _host()
    host.euid = 1000
    host.users["wirescope"] = "wirescope"
    host.groups["wirescope"] = {"wirescope"}
    host.groups["wireshark"] = {"wirescope"}
    config = _config(tmp_path, user_session=True, start_services=True)
    report = install(config, host)
    api_unit = host.read_text(config.paths.systemd_dir / "wirescope-api.service")
    worker_unit = host.read_text(
        config.paths.systemd_dir / "wirescope-worker.service"
    )
    assert "User=wirescope" not in api_unit
    assert "WantedBy=default.target" in api_unit
    assert "SupplementaryGroups=" not in api_unit
    assert "/usr/bin/sg wireshark" in api_unit
    assert "/usr/bin/sg wireshark" in worker_unit
    assert "ReadWritePaths=" not in api_unit
    assert any(item[:2] == ("systemctl", "--user") for item in host.commands)
    assert report.started == ["wirescope-api.service", "wirescope-worker.service"]
    assert any("dumpcap" in item for item in report.warnings)


def test_install_refuses_non_root(tmp_path):
    host = _host()
    host.euid = 1000
    config = _config(tmp_path)
    try:
        install(config, host)
    except InstallError as exc:
        assert "root" in str(exc)
    else:
        raise AssertionError("non-root install must fail")


def test_optional_unavailable_packages_are_skipped(tmp_path):
    host = _host()
    host.available_packages = set(REQUIRED_PACKAGES)
    config = _config(tmp_path, start_services=False)
    report = install(config, host)
    assert any("optional package unavailable: ssh-audit" in item for item in report.warnings)
    assert "ssh-audit" not in host.packages
    assert "nuclei" not in host.packages


def _rpm_host(platform):
    host = MemoryHost(platform=platform)
    host.files["/usr/bin/dumpcap"] = MemoryFile(
        content="",
        mode=0o755,
        owner="nobody",
        group="nogroup",
    )
    return host


def test_fedora_install_uses_dnf_and_wireshark_cli(tmp_path):
    host = _rpm_host(fedora_amd64_platform())
    config = _config(tmp_path, start_services=False, skip_pip=True)
    report = install(config, host)
    dnf = [item for item in host.commands if item and item[0] == "dnf"]
    assert dnf
    assert "install" in dnf[0]
    assert "wireshark-cli" in dnf[0]
    assert "nmap" in dnf[0]
    assert "tshark" not in dnf[0]
    assert "bind-utils" in dnf[0]
    assert host.user_exists("wirescope")
    assert host.user_in_group("wirescope", "wireshark")
    assert report.dumpcap is not None and report.dumpcap.ok
    assert report.platform.package_manager == "dnf"
    api_unit = host.read_text(config.paths.systemd_dir / "wirescope-api.service")
    assert "SupplementaryGroups=wireshark" in api_unit
    assert "User=wirescope" in api_unit


def test_opensuse_install_uses_zypper(tmp_path):
    host = _rpm_host(opensuse_amd64_platform())
    config = _config(tmp_path, start_services=False, skip_pip=True)
    install(config, host)
    zypper = [item for item in host.commands if item and item[0] == "zypper"]
    assert zypper
    assert "--non-interactive" in zypper[0]
    assert "libcap-progs" in zypper[0]


def test_public_bind_host_warns_for_lan_deploy(tmp_path):
    host = _host()
    config = _config(tmp_path, start_services=False, bind_host="0.0.0.0")
    report = install(config, host)
    assert any("public" in item.lower() for item in report.warnings)
    assert "WIRESCOPE_BIND_HOST=0.0.0.0" in host.read_text(config.paths.env_file)
    assert any("packaging/proxy" in item or "firewall" in item for item in report.warnings)


def test_trust_proxy_install_stays_on_loopback_and_copies_examples(tmp_path):
    host = _host()
    config = _config(
        tmp_path,
        start_services=False,
        skip_pip=True,
        apply_packages=False,
        trust_proxy=True,
        bind_host="127.0.0.1",
    )
    report = install(config, host)
    env = host.read_text(config.paths.env_file)
    assert "WIRESCOPE_TRUST_PROXY=true" in env
    assert "WIRESCOPE_SESSION_COOKIE_SECURE=true" in env
    assert host.exists(config.paths.etc_dir / "proxy" / "Caddyfile")
    assert "127.0.0.1:8000" in host.read_text(
        config.paths.etc_dir / "proxy" / "Caddyfile"
    )
    assert "proxy_pass http://127.0.0.1:8000" in host.read_text(
        config.paths.etc_dir / "proxy" / "nginx.conf"
    )
    assert host.exists(config.paths.etc_dir / "proxy" / "nftables.nft")
    assert host.exists(config.paths.etc_dir / "proxy" / "ufw.example")
    assert host.exists(config.paths.etc_dir / "proxy" / "firewalld.example")
    assert any("reverse proxy" in item or "cookie Secure" in item for item in report.steps)


def test_direct_tls_install_writes_cert_paths_not_pem(tmp_path):
    host = _host()
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    host.files[str(cert)] = MemoryFile(content="NOT-A-REAL-CERT", mode=0o644)
    host.files[str(key)] = MemoryFile(content="NOT-A-REAL-KEY", mode=0o600)
    config = _config(
        tmp_path,
        start_services=False,
        skip_pip=True,
        apply_packages=False,
        bind_host="0.0.0.0",
        bind_port=8443,
        tls_certfile=cert,
        tls_keyfile=key,
    )
    install(config, host)
    env = host.read_text(config.paths.env_file)
    assert f"WIRESCOPE_TLS_CERTFILE={cert}" in env
    assert "NOT-A-REAL-KEY" not in env
    assert "WIRESCOPE_SESSION_COOKIE_SECURE=true" in env
    api_unit = host.read_text(config.paths.systemd_dir / "wirescope-api.service")
    assert "User=wirescope" in api_unit
    assert "BEGIN " not in api_unit
    assert "AmbientCapabilities=" not in api_unit


