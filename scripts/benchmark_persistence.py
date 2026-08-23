"""Small local benchmark for the durable execution foundation."""

from dataclasses import replace
import json
from pathlib import Path
from statistics import median
import tempfile
from time import perf_counter

from config.settings import get_settings
from jobs.models import JobProgress, RetentionClass
from jobs.service import JobService
from persistence.database import Database
from persistence.schema import apply_migrations
from storage.evidence import EvidenceStore


def milliseconds(started: float) -> float:
    return round((perf_counter() - started) * 1_000, 3)


def main(iterations: int = 50) -> None:
    with tempfile.TemporaryDirectory(prefix="wirescope-benchmark-") as temp:
        root = Path(temp)
        settings = replace(
            get_settings(),
            database_path=root / "wirescope.db",
            evidence_dir=root / "evidence",
            runtime_dir=root / "runtime",
            capture_dir=root / "runtime" / "captures",
        )
        started = perf_counter()
        apply_migrations(settings)
        migration_ms = milliseconds(started)

        started = perf_counter()
        database = Database(settings)
        service = JobService(database)
        evidence = EvidenceStore(database, settings)
        startup_ms = milliseconds(started)

        audit = service.create_audit(
            profile="benchmark",
            interface="fixture0",
        )
        create_times = []
        jobs = []
        for index in range(iterations):
            started = perf_counter()
            jobs.append(
                service.create_job(
                    audit_id=audit.id,
                    job_type="benchmark",
                    target=f"fixture:{index}",
                )
            )
            create_times.append(milliseconds(started))

        update_times = []
        event_times = []
        result_times = []
        for job in jobs:
            service.claim_next("benchmark-worker")
            started = perf_counter()
            service.update_progress(
                job.id,
                JobProgress(
                    percentage=50,
                    stage="benchmark",
                    message="Benchmark update",
                ),
            )
            update_times.append(milliseconds(started))
            started = perf_counter()
            artifact = evidence.put_json(
                audit_id=audit.id,
                job_id=job.id,
                artifact_type="benchmark_result",
                document={
                    "schema": "benchmark-result",
                    "schema_version": 1,
                    "payload": "x" * 2048,
                },
                retention_class=RetentionClass.DEBUG,
                schema_name="benchmark-result",
                schema_version=1,
            )
            result_times.append(milliseconds(started))
            started = perf_counter()
            service.complete_job(
                job.id,
                result_reference=artifact.id,
            )
            event_times.append(milliseconds(started))

        started = perf_counter()
        page = service.list_jobs(limit=100, offset=0)
        list_ms = milliseconds(started)
        database.dispose()
        print(
            json.dumps(
                {
                    "iterations": iterations,
                    "migration_ms": migration_ms,
                    "startup_ms": startup_ms,
                    "job_create_median_ms": median(create_times),
                    "progress_event_median_ms": median(update_times),
                    "result_2kb_median_ms": median(result_times),
                    "completion_event_median_ms": median(event_times),
                    "list_50_jobs_ms": list_ms,
                    "listed_jobs": page.total,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
