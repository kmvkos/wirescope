import os

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

    stale_capture = (
        durable_settings.capture_dir / "wirescope_interrupted"
    )
    stale_capture.mkdir(parents=True)
    (stale_capture / "capture.pcap").write_bytes(b"partial")
    os.utime(stale_capture, (1, 1))
    unrelated = durable_settings.capture_dir / "operator-data"
    unrelated.mkdir()
    os.utime(unrelated, (1, 1))

    result = MaintenanceService(
        database,
        evidence_store,
        durable_settings,
    ).run_startup_cleanup()

    assert result == {
        "stale_temporary_files": 1,
        "orphan_files": 1,
        "stale_capture_directories": 1,
    }
    assert unrelated.exists()
