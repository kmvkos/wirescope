from pathlib import Path

import pytest

from appliance.detect import (
    UnsupportedPlatformError,
    detect_platform,
    normalize_arch,
    parse_os_release,
)
from appliance.dumpcap import configure_dumpcap, inspect_dumpcap
from appliance.host import MemoryFile, MemoryHost, debian_amd64_platform
from appliance.kiosk import KIOSK_SCRIPT, kiosk_recovers_without_stopping_backend
from appliance.packages import FORBIDDEN_DEFAULT_PACKAGES, select_packages
from appliance.paths import (
    DEFAULT_PROJECT_ROOT,
    RECOMMENDED_PROJECT_ROOT,
    InstallPaths,
    discover_project_root,
    production_env_text,
)
from appliance.recovery import describe_reboot_recovery
from appliance.release import checksum_paths, render_checksums
from appliance.systemd import SECRET_HINTS, unit_files
from tests.fixtures.os_release import os_release


DEBIAN_OS_RELEASE = os_release("debian-13")
RASPI_OS_RELEASE = os_release("raspi-os")


def test_detect_current_host_is_supported_linux():
    platform = detect_platform()
    assert platform.family in {"debian", "rhel", "suse"}
    assert platform.package_manager in {"apt", "dnf", "yum", "zypper"}
    assert platform.arch in {"amd64", "arm64"}
    assert platform.supported is True


def test_detect_debian_amd64_and_arm64():
    amd = detect_platform(os_release_text=DEBIAN_OS_RELEASE, machine="x86_64")
    arm = detect_platform(
        os_release_text=RASPI_OS_RELEASE,
        machine="aarch64",
        model_text="Raspberry Pi 4 Model B",
    )
    assert amd.family == "debian"
    assert amd.package_manager == "apt"
    assert amd.arch == "amd64"
    assert amd.raspberry_pi is False
    assert arm.arch == "arm64"
    assert arm.raspberry_pi is True
    assert arm.supported is True
    assert normalize_arch("x86_64") == "amd64"
    assert parse_os_release(DEBIAN_OS_RELEASE)["ID"] == "debian"


def test_detect_rejects_unsupported_family_and_arch():
    with pytest.raises(UnsupportedPlatformError, match="unsupported OS"):
        detect_platform(os_release_text='ID="alpine"\n', machine="x86_64")
    with pytest.raises(UnsupportedPlatformError, match="unsupported architecture"):
        detect_platform(os_release_text=DEBIAN_OS_RELEASE, machine="ppc64le")


def test_default_packages_exclude_nuclei_nikto_and_kiosk():
    selected = select_packages(optional_providers=True, kiosk=False)
    assert "tshark" in selected.required
    assert "nmap" in selected.optional
    assert selected.kiosk == ()
    assert FORBIDDEN_DEFAULT_PACKAGES.isdisjoint(selected.all_selected)
    assert "nuclei" not in selected.all_selected
    assert "nikto" not in selected.all_selected
    assert "chromium" not in selected.all_selected


def test_rhel_packages_map_dumpcap_and_nmap_names():
    selected = select_packages(family="rhel", optional_providers=True, kiosk=False)
    assert "wireshark-cli" in selected.required
    assert "nmap" in selected.optional
    assert "bind-utils" in selected.optional
    assert selected.kiosk == ()


def test_dumpcap_configuration_does_not_cap_backend_python():
    host = MemoryHost(platform=debian_amd64_platform())
    dumpcap = Path("/usr/bin/dumpcap")
    python = Path("/opt/wirescope/.venv/bin/python")
    host.files[str(dumpcap)] = MemoryFile(
        content="",
        mode=0o755,
        owner="nobody",
        group="nogroup",
        capabilities="",
        setuid=True,
    )
    host.files[str(python)] = MemoryFile(content="", mode=0o755)
    host.users["wirescope"] = "wirescope"
    host.groups["wirescope"] = {"wirescope"}
    report = configure_dumpcap(
        host,
        dumpcap_path=dumpcap,
        service_user="wirescope",
        venv_python=python,
    )
    assert report.ok is True
    assert report.setuid is False
    assert host.file_owner(dumpcap) == "root"
    assert host.file_group(dumpcap) == "wireshark"
    assert host.file_mode(dumpcap) == 0o750
    assert "cap_net_raw" in report.capabilities
    assert host.getcap(python) == ""
    assert host.user_in_group("wirescope", "wireshark")


def test_inspect_dumpcap_fails_when_python_has_net_raw():
    host = MemoryHost(platform=debian_amd64_platform())
    dumpcap = Path("/usr/bin/dumpcap")
    python = Path("/usr/bin/python3")
    host.files[str(dumpcap)] = MemoryFile(
        owner="root",
        group="wireshark",
        mode=0o750,
        capabilities="cap_net_admin,cap_net_raw=eip",
    )
    host.files[str(python)] = MemoryFile(
        capabilities="cap_net_raw=eip",
    )
    host.users["wirescope"] = "wirescope"
    host.groups["wireshark"] = {"wirescope"}
    host.binaries["python3"] = str(python)
    report = inspect_dumpcap(
        host,
        dumpcap_path=dumpcap,
        service_user="wirescope",
        venv_python=python,
    )
    assert report.ok is False
    assert "backend_capabilities" in report.issues


def test_systemd_units_have_no_secrets_and_keep_worker_uncapped():
    files = {unit.name: unit.content for unit in unit_files(InstallPaths())}
    combined = "\n".join(files.values())
    for hint in SECRET_HINTS:
        assert hint not in combined.upper()
    assert "User=root" not in combined
    assert "AmbientCapabilities=" not in combined
    assert "User=wirescope" in files["wirescope-api.service"]
    assert "python -m backend" in files["wirescope-api.service"]
    assert "NoNewPrivileges=" not in files["wirescope-api.service"]
    assert "/etc/network" in files["wirescope-api.service"]
    assert "NoNewPrivileges" not in files["wirescope-worker.service"]
    assert "python -m jobs.worker" in files["wirescope-worker.service"]
    assert "After=wirescope-api.service getty@tty1.service systemd-user-sessions.service" in files["wirescope-kiosk.service"]
    assert "PartOf=wirescope-worker" not in files["wirescope-kiosk.service"]
    assert "WantedBy=multi-user.target" in files["wirescope-kiosk.service"]
    assert "Conflicts=getty@tty1.service" in files["wirescope-kiosk.service"]
    assert "OnFailure=getty@tty1.service" in files["wirescope-kiosk.service"]
    assert "graphical.target" not in files["wirescope-kiosk.service"]
    assert "appliance wait-ready" in files["wirescope-kiosk.service"]
    assert "PrivateTmp=" not in files["wirescope-kiosk.service"]
    assert "StartLimitBurst=5" in files["wirescope-api.service"]
    assert "SupplementaryGroups=wireshark" in files["wirescope-api.service"]
    assert "SupplementaryGroups=wireshark" in files["wirescope-worker.service"]
    assert "/usr/bin/sg " not in files["wirescope-api.service"]
    assert "/usr/bin/sg " not in files["wirescope-worker.service"]
    env = production_env_text(
        InstallPaths(),
        bind_host="127.0.0.1",
        bind_port=8000,
    )
    assert "WIRESCOPE_DOCS_ENABLED=false" in env
    assert "WIRESCOPE_TRUST_PROXY=false" in env
    assert "PASSWORD" not in env


def test_user_session_units_rejoin_wireshark_without_logout():
    files = {
        unit.name: unit.content
        for unit in unit_files(InstallPaths(), user_session=True)
    }
    api = files["wirescope-api.service"]
    worker = files["wirescope-worker.service"]
    assert "User=" not in api
    assert "SupplementaryGroups=" not in api
    assert "SupplementaryGroups=" not in worker
    assert "NoNewPrivileges" not in api
    assert '/usr/bin/sg wireshark -c "' in api
    assert '/usr/bin/sg wireshark -c "' in worker
    assert "ReadWritePaths=" not in api
    assert "ReadWritePaths=" not in worker
    assert "python -m backend" in api
    assert "python -m jobs.worker" in worker
    assert "WantedBy=default.target" in api
    kiosk = files["wirescope-kiosk.service"]
    assert "WantedBy=graphical-session.target" in kiosk
    assert "PassEnvironment=DISPLAY WAYLAND_DISPLAY XAUTHORITY" in kiosk


def test_packaged_units_match_renderer():
    root = Path(__file__).resolve().parents[1] / "packaging" / "systemd"
    for unit in unit_files(InstallPaths()):
        packaged = (root / unit.name).read_text(encoding="utf-8")
        assert packaged == unit.content


def test_kiosk_script_recovers_without_stopping_audits():
    assert kiosk_recovers_without_stopping_backend(KIOSK_SCRIPT)
    assert "--window-size=480,320" in KIOSK_SCRIPT
    assert "127.0.0.1:8000" in KIOSK_SCRIPT


def test_reboot_recovery_policy_is_explicit():
    policy = describe_reboot_recovery()
    assert policy["error_code"] == "application_restart"
    assert policy["automatic_retry"] is False
    assert "queued" in policy["queued"]
    assert "interrupted" in policy["running"]


def test_checksums_cover_packaging_files(tmp_path):
    sample = tmp_path / "install.sh"
    sample.write_text("#!/bin/sh\n", encoding="utf-8")
    records = checksum_paths([sample], root=tmp_path)
    rendered = render_checksums(records)
    assert records[0].algorithm == "sha256"
    assert records[0].relative_path == "install.sh"
    assert records[0].digest in rendered


def test_discover_project_root_finds_checkout_with_packaging():
    checkout = Path(__file__).resolve().parents[1]
    found = discover_project_root()
    assert found == checkout
    assert (found / "packaging" / "install.sh").is_file()


def test_discover_project_root_from_clone_elsewhere(tmp_path):
    clone = tmp_path / "wirescope-clone"
    script = clone / "packaging" / "install.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    nested = clone / "appliance" / "paths.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("", encoding="utf-8")
    assert discover_project_root(nested) == clone


def test_discover_project_root_falls_back_to_recommended(tmp_path):
    orphan = tmp_path / "not-a-checkout" / "module.py"
    orphan.parent.mkdir(parents=True)
    orphan.write_text("", encoding="utf-8")
    assert discover_project_root(orphan) == RECOMMENDED_PROJECT_ROOT
    assert DEFAULT_PROJECT_ROOT == Path("/opt/wirescope")


def test_install_sh_uses_checkout_directory_as_project_root():
    root = Path(__file__).resolve().parents[1]
    text = (root / "packaging" / "install.sh").read_text(encoding="utf-8")
    assert '--project-root "$here"' in text
    assert "dirname" in text
    assert text.count("/opt/wirescope") <= 1
