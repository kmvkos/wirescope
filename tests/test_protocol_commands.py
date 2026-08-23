from config.settings import get_settings
from protocol_audits.modules.dns import DnsModule
from protocol_audits.modules.http import HttpModule
from protocol_audits.modules.ldap import LdapModule
from protocol_audits.modules.smb import SmbModule
from protocol_audits.modules.snmp import SnmpModule
from protocol_audits.modules.ssh import SshModule
from protocol_audits.modules.tls import TlsModule
from tests.helpers import sample_service, sample_target


def test_ssh_command_is_argv_only_and_uses_inventory_address():
    command = SshModule().build_command(sample_target(), get_settings())
    assert command.argv[0] == "ssh-audit"
    assert command.argv[1:] == ["-n", "-p", "22", "192.0.2.10"]
    assert all(not arg.startswith(";") for arg in command.argv)
    assert "-T5" not in command.argv


def test_tls_command_uses_connect_and_validated_servername():
    command = TlsModule().build_command(sample_target(
        service=sample_service(port=443, name="https", product="nginx"),
        port=443,
        scheme_hint="tls",
    ), get_settings())
    assert command.argv[:3] == ["openssl", "s_client", "-connect"]
    assert command.argv[3] == "192.0.2.10:443"
    assert command.argv[4:6] == ["-servername", "linux.example.test"]
    assert "--starttls" not in command.argv
    assert "-T5" not in command.argv


def test_tls_rejects_flag_like_hostnames_and_falls_back_to_ip():
    target = sample_target(
        service=sample_service(port=443, name="https"),
        port=443,
        hostname="-connect",
    )
    command = TlsModule().build_command(target, get_settings())
    assert command.argv[command.argv.index("-servername") + 1] == "192.0.2.10"


def test_http_command_does_not_follow_redirects_or_enable_nuclei():
    command = HttpModule().build_command(sample_target(
        service=sample_service(port=80, name="http", product="nginx"),
        port=80,
        scheme_hint="http",
    ), get_settings())
    assert command.argv[0] == "curl"
    assert "--max-redirs" in command.argv
    assert command.argv[command.argv.index("--max-redirs") + 1] == "0"
    assert command.argv[-1] == "http://192.0.2.10:80/"
    assert "nikto" not in command.argv
    assert "nuclei" not in command.argv


def test_https_http_module_uses_insecure_https_url():
    command = HttpModule().build_command(sample_target(
        service=sample_service(port=443, name="https", tunnel="ssl"),
        port=443,
        scheme_hint="tls",
    ), get_settings())
    assert command.argv[-1] == "https://192.0.2.10:443/"
    assert "--insecure" in command.argv


def test_dns_commands_stay_in_scope_and_do_not_query_the_internet():
    commands = DnsModule().build_commands(sample_target(
        service=sample_service(port=53, protocol="udp", name="domain"),
        port=53,
    ), get_settings())
    assert len(commands) == 2
    for command in commands:
        assert command.argv[0] == "dig"
        assert "@192.0.2.10" in command.argv
        assert "+norecurse" in command.argv
        assert "example.com" not in command.argv
        assert "google.com" not in command.argv
        assert "CH" in command.argv


def test_smb_command_is_unauthenticated():
    command = SmbModule().build_command(sample_target(
        service=sample_service(port=445, name="microsoft-ds"),
        port=445,
    ), get_settings())
    assert command.argv[:4] == ["smbclient", "-N", "-L", "//192.0.2.10"]
    assert "-U" not in command.argv
    assert "--password" not in command.argv


def test_snmp_command_does_not_guess_communities():
    command = SnmpModule().build_command(sample_target(
        service=sample_service(port=161, protocol="udp", name="snmp"),
        port=161,
    ), get_settings())
    assert "-v3" in command.argv
    assert "-c" not in command.argv
    assert "public" not in command.argv
    assert "private" not in command.argv
    assert command.argv[-1] == "1.3.6.1.2.1.1.1.0"


def test_ldap_command_is_anonymous_bind_only():
    command = LdapModule().build_command(sample_target(
        service=sample_service(port=389, name="ldap"),
        port=389,
    ), get_settings())
    assert command.argv[:6] == [
        "ldapsearch",
        "-x",
        "-LLL",
        "-H",
        "ldap://192.0.2.10:389",
        "-s",
    ]
    assert "-D" not in command.argv
    assert "-w" not in command.argv
    assert "-W" not in command.argv
