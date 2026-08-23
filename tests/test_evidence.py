import hashlib
import os

import pytest

from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, RetentionClass


def audit_and_job(job_service):
    audit = job_service.create_audit(
        profile="passive",
        interface="eth0",
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="test",
        target="eth0",
    )
    return audit, job


def test_json_artifact_is_atomic_hashed_and_readable(
    job_service,
    evidence_store,
):
    audit, job = audit_and_job(job_service)
    document = {"schema": "test-result", "schema_version": 1, "value": 42}

    artifact = evidence_store.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="test_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="test-result",
        schema_version=1,
    )

    path = evidence_store.path_for(artifact)
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert artifact.size == len(path.read_bytes())
    assert artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert evidence_store.read_json(artifact) == document
    assert list(evidence_store.root.rglob("*.tmp-*")) == []


def test_file_import_and_orphan_cleanup(
    tmp_path,
    job_service,
    evidence_store,
):
    audit, job = audit_and_job(job_service)
    source = tmp_path / "capture.pcap"
    source.write_bytes(b"pcap fixture")

    artifact = evidence_store.import_file(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="packet_capture",
        source=source,
        content_type="application/vnd.tcpdump.pcap",
        extension=".pcap",
        retention_class=RetentionClass.AUDIT,
    )
    orphan = evidence_store.root / "orphan.bin"
    orphan.write_bytes(b"orphan")
    os.utime(orphan, (1, 1))

    assert evidence_store.path_for(artifact).read_bytes() == b"pcap fixture"
    assert evidence_store.cleanup_orphan_files() == 1
    assert not orphan.exists()


def test_stale_temporary_file_cleanup(evidence_store):
    temporary = evidence_store.root / "result.json.tmp-dead"
    temporary.write_bytes(b"incomplete")
    os.utime(temporary, (1, 1))

    assert (
        evidence_store.cleanup_stale_temporary_files(
            older_than_seconds=1
        )
        == 1
    )
    assert not temporary.exists()


def test_storage_failure_is_structured(
    job_service,
    evidence_store,
):
    audit, job = audit_and_job(job_service)
    evidence_store.root.rmdir()
    evidence_store.root.write_bytes(b"not a directory")

    with pytest.raises(JobExecutionError) as captured:
        evidence_store.put_json(
            audit_id=audit.id,
            job_id=job.id,
            artifact_type="test_result",
            document={"schema": "test", "schema_version": 1},
            retention_class=RetentionClass.AUDIT,
            schema_name="test",
            schema_version=1,
        )

    assert captured.value.error.category == ErrorCategory.STORAGE
