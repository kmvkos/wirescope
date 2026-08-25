import os

from backend.snmp_credentials import SnmpCredentialSpool
from backend.ssh_credentials import SshCredentialSpool
from jobs.maintenance import MaintenanceService


def test_startup_cleanup_removes_only_stale_runtime_files(
    durable_settings,
    database,
    evidence_store,
):
    temporary = evidence_store.root / "result.tmp-crash"
    temporary.write_bytes(b"partial")
    os.utime(temporary, (1, 1))
    orphan = evidence_store.root / "orphan.json"
    orphan.write_text("{}", encoding="utf-8")
    os.utime(orphan, (1, 1))

    stale_capture = (
        durable_settings.capture_dir / "wirescope_interrupted"
    )
    stale_capture.mkdir(parents=True)
    (stale_capture / "capture.pcap").write_bytes(b"partial")
    os.utime(stale_capture, (1, 1))
    unrelated = durable_settings.capture_dir / "operator-data"
    unrelated.mkdir()
    os.utime(unrelated, (1, 1))

    credential_spool = SnmpCredentialSpool(durable_settings)
    stale_reference = credential_spool.put({"version": "2c", "community": "temporary-secret"})
    stale_secret = credential_spool._path(stale_reference)
    os.utime(stale_secret, (1, 1))

    ssh_spool = SshCredentialSpool(durable_settings)
    stale_ssh_reference = ssh_spool.put(
        {
            "username": "audit",
            "authentication": "private_key",
            "private_key": "temporary-private-key",
            "known_hosts": "10.11.11.11 ssh-ed25519 AAAA",
        }
    )
    stale_ssh_secret = ssh_spool._path(stale_ssh_reference)
    os.utime(stale_ssh_secret, (1, 1))

    result = MaintenanceService(
        database,
        evidence_store,
        durable_settings,
    ).run_startup_cleanup()

    assert result == {
        "stale_temporary_files": 1,
        "orphan_files": 1,
        "stale_capture_directories": 1,
        "stale_snmp_credentials": 1,
        "stale_ssh_topology_credentials": 1,
    }
    assert unrelated.exists()
    assert not stale_secret.exists()
    assert not stale_ssh_secret.exists()
