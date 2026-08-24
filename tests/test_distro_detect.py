from appliance.detect import (
    UnsupportedPlatformError,
    classify_family,
    detect_platform,
    normalize_arch,
    parse_os_release,
    probe_package_managers,
    select_package_manager,
)
from appliance.packages import package_install_argv, select_packages
from tests.fixtures.os_release import os_release


def test_detect_current_host_is_supported_linux():
    platform = detect_platform()
    assert platform.family in {"debian", "rhel", "suse"}
    assert platform.package_manager in {"apt", "dnf", "yum", "zypper"}
    assert platform.arch in {"amd64", "arm64"}
    assert platform.supported is True


def test_detect_debian_and_ubuntu_use_apt():
    debian = detect_platform(
        os_release_text=os_release("debian-13"),
        machine="x86_64",
    )
    ubuntu = detect_platform(
        os_release_text=os_release("ubuntu-24.04"),
        machine="x86_64",
    )
    assert debian.family == "debian"
    assert debian.package_manager == "apt"
    assert debian.arch == "amd64"
    assert debian.raspberry_pi is False
    assert ubuntu.family == "debian"
    assert ubuntu.package_manager == "apt"
    assert ubuntu.distro_id == "ubuntu"
    assert parse_os_release(os_release("debian-13"))["ID"] == "debian"
    assert classify_family(parse_os_release(os_release("ubuntu-24.04"))) == "debian"


def test_detect_fedora_and_rocky_use_dnf_or_yum():
    fedora = detect_platform(
        os_release_text=os_release("fedora-41"),
        machine="x86_64",
    )
    rocky_dnf = detect_platform(
        os_release_text=os_release("rocky-9"),
        machine="x86_64",
        available_package_managers=("dnf", "yum"),
    )
    rocky_yum = detect_platform(
        os_release_text=os_release("rocky-9"),
        machine="x86_64",
        available_package_managers=("yum",),
    )
    assert fedora.family == "rhel"
    assert fedora.package_manager == "dnf"
    assert fedora.distro_id == "fedora"
    assert rocky_dnf.family == "rhel"
    assert rocky_dnf.package_manager == "dnf"
    assert rocky_yum.package_manager == "yum"
    assert classify_family(parse_os_release(os_release("rocky-9"))) == "rhel"


def test_detect_opensuse_uses_zypper():
    suse = detect_platform(
        os_release_text=os_release("opensuse-leap"),
        machine="aarch64",
    )
    assert suse.family == "suse"
    assert suse.package_manager == "zypper"
    assert suse.arch == "arm64"
    assert suse.supported is True


def test_raspberry_pi_is_optional_debian_arm64():
    pi = detect_platform(
        os_release_text=os_release("raspi-os"),
        machine="aarch64",
        model_text="Raspberry Pi 4 Model B",
    )
    assert pi.family == "debian"
    assert pi.package_manager == "apt"
    assert pi.arch == "arm64"
    assert pi.raspberry_pi is True
    assert pi.supported is True


def test_detect_rejects_unsupported_family_and_arch():
    try:
        detect_platform(os_release_text=os_release("alpine"), machine="x86_64")
    except UnsupportedPlatformError as exc:
        assert "unsupported OS family" in str(exc)
    else:
        raise AssertionError("alpine must be rejected")
    try:
        detect_platform(
            os_release_text=os_release("debian-13"),
            machine="ppc64le",
        )
    except UnsupportedPlatformError as exc:
        assert "unsupported architecture" in str(exc)
    else:
        raise AssertionError("ppc64le must be rejected")


def test_package_manager_probe_and_family_preference():
    assert probe_package_managers(which={"dnf": "/usr/bin/dnf"}) == ("dnf",)
    assert select_package_manager("rhel", ("yum",)) == "yum"
    assert select_package_manager("debian", None) == "apt"
    assert normalize_arch("x86_64") == "amd64"
    assert normalize_arch("aarch64") == "arm64"


def test_package_names_differ_by_family():
    debian = select_packages(family="debian")
    rhel = select_packages(family="rhel")
    suse = select_packages(family="suse")
    assert "tshark" in debian.required
    assert "wireshark-common" in debian.required
    assert "nmap" in debian.optional
    assert "bind9-dnsutils" in debian.optional
    assert "wireshark-cli" in rhel.required
    assert "tshark" not in rhel.required
    assert "python3-devel" in rhel.required
    assert "iproute" in rhel.required
    assert "bind-utils" in rhel.optional
    assert "samba-client" in rhel.optional
    assert "libcap-progs" in suse.required
    assert debian.kiosk == ()
    assert "nuclei" not in rhel.all_selected
    apt_cmd = package_install_argv("apt", ("tshark",))
    assert apt_cmd[0] == "apt-get"
    assert "-y" in apt_cmd
    assert any("force-confdef" in part for part in apt_cmd)
    assert any("force-confold" in part for part in apt_cmd)
    assert package_install_argv("dnf", ("wireshark-cli",))[:3] == [
        "dnf",
        "install",
        "-y",
    ]
    assert package_install_argv("yum", ("nmap",))[0] == "yum"
    assert package_install_argv("zypper", ("nmap",))[0] == "zypper"
