from pathlib import Path
import sqlite3

from jobs.models import JobStatus
from tests.test_job_service import create_job

from appliance.backup import create_backup, restore_backup
from appliance.bootstrap import (
    BootstrapError,
    create_initial_operators,
    write_password_file,
)
from appliance.recovery import describe_reboot_recovery


def test_create_initial_auditor_once(durable_settings, database):
    created = create_initial_operators(
        durable_settings,
        auditor_username="auditor",
        auditor_password="initial-pass",
        viewer_username="viewer",
        viewer_password="viewer-pass",
        database=database,
    )
    again = create_initial_operators(
        durable_settings,
        auditor_username="auditor",
        auditor_password="initial-pass",
        database=database,
    )
    assert created == ["auditor", "viewer"]
    assert again == []


def test_password_file_rejects_world_readable(tmp_path):
    path = tmp_path / "password"
    path.write_text("supersecret\n", encoding="utf-8")
    path.chmod(0o644)
    try:
        from appliance.bootstrap import read_password_file

        read_password_file(path)
    except BootstrapError as exc:
        assert "0600" in str(exc)
    else:
        raise AssertionError("world-readable password file must be rejected")


def test_write_password_file_is_owner_only(tmp_path):
    path = write_password_file(tmp_path / "secret", "supersecret")
    assert path.stat().st_mode & 0o777 == 0o600


def test_backup_and_restore_roundtrip(tmp_path):
    data = tmp_path / "data"
    database = data / "wirescope.db"
    evidence = data / "evidence"
    backups = data / "backups"
    evidence.mkdir(parents=True)
    (evidence / "note.txt").write_text("keep", encoding="utf-8")
    conn = sqlite3.connect(database)
    conn.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO sample(name) VALUES ('alpha')")
    conn.commit()
    conn.close()

    archive = create_backup(
        database_path=database,
        evidence_dir=evidence,
        backup_dir=backups,
    )
    conn = sqlite3.connect(database)
    conn.execute("UPDATE sample SET name='mutated'")
    conn.commit()
    conn.close()
    (evidence / "note.txt").write_text("changed", encoding="utf-8")

    restore_backup(
        archive,
        database_path=database,
        evidence_dir=evidence,
    )
    conn = sqlite3.connect(database)
    name = conn.execute("SELECT name FROM sample").fetchone()[0]
    conn.close()
    assert name == "alpha"
    assert (evidence / "note.txt").read_text(encoding="utf-8") == "keep"


def test_reboot_leaves_queued_jobs_and_interrupts_running(job_service):
    _audit, running = create_job(job_service, interface="eth0")
    queued = job_service.create_job(
        audit_id=_audit.id,
        job_type="passive_discovery",
        target="eth1",
        resource_key="interface:eth1",
    )
    assert job_service.claim_next("old-worker").id == running.id
    recovered = job_service.recover_after_restart()
    policy = describe_reboot_recovery()
    assert recovered == 1
    assert job_service.get_job(running.id).status == JobStatus.INTERRUPTED
    assert job_service.get_job(running.id).error.code == "application_restart"
    assert job_service.get_job(queued.id).status == JobStatus.QUEUED
    assert policy["automatic_retry"] is False
