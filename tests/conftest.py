from dataclasses import replace

import pytest

from config.settings import get_settings
from jobs.service import JobService
from persistence.database import Database
from persistence.schema import apply_migrations
from storage.evidence import EvidenceStore


@pytest.fixture
def durable_settings(tmp_path):
    return replace(
        get_settings(),
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "wirescope.db",
        evidence_dir=tmp_path / "data" / "evidence",
        runtime_dir=tmp_path / "data" / "runtime",
        capture_dir=tmp_path / "data" / "runtime" / "captures",
        nmap_runtime_dir=tmp_path / "data" / "runtime" / "nmap",
        protocol_runtime_dir=tmp_path / "data" / "runtime" / "protocol",
        worker_poll_interval_seconds=0.02,
        worker_heartbeat_interval_seconds=0.05,
        worker_stale_after_seconds=2,
    )


@pytest.fixture
def database(durable_settings):
    apply_migrations(durable_settings)
    active = Database(durable_settings)
    yield active
    active.dispose()


@pytest.fixture
def job_service(database):
    return JobService(database)


@pytest.fixture
def evidence_store(database, durable_settings):
    return EvidenceStore(database, durable_settings)
