from types import SimpleNamespace

import pytest

from config.settings import get_settings
from providers.ssh_topology import (
    SshTopologyCredentialError,
    SshTopologyProvider,
    _parse_station_dump,
    sanitize_ssh_profile,
)


class _Runner:
    def __init__(self):
        self.commands = []

    def run(self, command, cancellation_token=None):
        self.commands.append(command)
        return SimpleNamespace(success=True, stdout="[]", stderr="", timed_out=False)


def test_ssh_remote_argv_has_strict_trust_and_no_remote_separator(tmp_path):
    runner = _Runner()
    provider = SshTopologyProvider(settings=get_settings(), runner=runner)
    identity = tmp_path / "identity"
    known_hosts = tmp_path / "known_hosts"

    provider._run(
        target="10.11.11.11",
        profile={"username": "audit", "port": 22, "authentication": "private_key"},
        identity_file=identity,
        known_hosts_file=known_hosts,
        remote_args=["ip", "-j", "addr", "show"],
        cancellation_token=None,
    )

    command = runner.commands[0]
    assert command.tool == "ssh"
    assert "StrictHostKeyChecking=yes" in command.args
    destination = command.args.index("audit@10.11.11.11")
    assert command.args[destination + 1 :] == ["ip", "-j", "addr", "show"]
    assert "--" not in command.args[destination + 1 :]


def test_ssh_profile_rejects_missing_host_key_and_operator_command_fields():
    with pytest.raises(SshTopologyCredentialError):
        sanitize_ssh_profile(
            {
                "username": "audit",
                "port": 22,
                "authentication": "agent",
                "known_hosts": "",
            }
        )

    profile = sanitize_ssh_profile(
        {
            "username": "audit",
            "port": 2222,
            "authentication": "agent",
            "known_hosts": "10.11.11.11 ssh-ed25519 AAAA",
            "command": "rm -rf /",
        }
    )
    assert profile == {
        "username": "audit",
        "port": 2222,
        "authentication": "agent",
        "host_key_verification": "strict",
    }


def test_iw_station_dump_normalizes_wifi_association():
    rows = _parse_station_dump(
        """
Station aa:bb:cc:dd:ee:ff (on wlan0)
        signal:         -51 dBm
        rx bytes:       12345
        tx bytes:       67890
        rx packets:     100
        tx packets:     80
""",
        "wlan0",
    )
    assert rows == [
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "interface": "wlan0",
            "signal_dbm": -51,
            "rx_bytes": 12345,
            "tx_bytes": 67890,
            "rx_packets": 100,
            "tx_packets": 80,
        }
    ]
