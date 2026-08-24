"""Controlled local durable worker and process entry point."""

import os
import signal
import socket
import threading
import time
import traceback
from typing import Any

from config.logging import bind_log_context, get_logger
from config.settings import Settings, get_settings
from jobs.errors import JobCancelled, JobExecutionError
from jobs.handlers import (
    ActiveDiscoveryHandler,
    FindingsEvaluationHandler,
    PassiveDiscoveryHandler,
    ProtocolAuditHandler,
    ReportGenerationHandler,
)
from jobs.maintenance import MaintenanceService
from jobs.models import AuditRecord, ErrorCategory, JobError, JobRecord
from jobs.registry import HandlerContext, HandlerRegistry
from jobs.service import JobService
from persistence.database import Database
from providers.tools import CancellationToken
from storage.evidence import EvidenceStore


class JobWorker:
    def __init__(
        self,
        *,
        worker_id: str,
        service: JobService,
        registry: HandlerRegistry,
        evidence_store: EvidenceStore,
        settings: Settings,
    ) -> None:
        self.worker_id = worker_id
        self.service = service
        self.registry = registry
        self.evidence_store = evidence_store
        self.settings = settings
        self.logger = get_logger("job_worker")
        self._registered = False

    def startup(self) -> None:
        self.service.register_worker(self.worker_id)
        self.service.heartbeat_worker(self.worker_id, status="idle")
        self._registered = True

    def run_once(self) -> bool:
        if not self._registered:
            self.startup()
        self.service.heartbeat_worker(self.worker_id, status="idle")
        job = self.service.claim_next(self.worker_id)
        if job is None:
            return False

        audit = self.service.get_audit(job.audit_id)
        with bind_log_context(
            audit_id=job.audit_id,
            job_id=job.id,
            worker_id=self.worker_id,
        ):
            self._execute(job, audit)
        return True

    def _execute(self, job: JobRecord, audit: AuditRecord) -> None:
        token = CancellationToken()
        monitor_stop = threading.Event()
        monitor = threading.Thread(
            target=self._monitor_cancellation,
            args=(job.id, token, monitor_stop),
            daemon=True,
            name=f"cancel-{job.id}",
        )
        monitor.start()
        self.service.heartbeat_worker(
            self.worker_id,
            status="running",
            current_job_id=job.id,
        )
        self.logger.info(
            "job execution started",
            extra={
                "job_id": job.id,
                "audit_id": job.audit_id,
                "job_type": job.type,
                "worker_id": self.worker_id,
            },
        )

        try:
            handler = self.registry.resolve(job.type)
            result = handler.execute(
                HandlerContext(
                    audit=audit,
                    job=job,
                    settings=self.settings,
                    cancellation_token=token,
                    evidence_store=self.evidence_store,
                    report_progress=lambda progress: (
                        self.service.update_progress(job.id, progress)
                    ),
                )
            )
            current = self.service.get_job(job.id)
            if token.cancelled or current.cancel_requested:
                self.service.cancel_running_job(job.id)
            else:
                self.service.complete_job(
                    job.id,
                    result_reference=result.result_reference,
                    summary=result.summary,
                )
        except JobCancelled as exc:
            self.service.cancel_running_job(
                job.id,
                message=exc.error.message,
            )
        except JobExecutionError as exc:
            current = self.service.get_job(job.id)
            if token.cancelled or current.cancel_requested:
                self.service.cancel_running_job(job.id)
            else:
                self.service.fail_job(job.id, exc.error)
        except Exception as exc:
            self.logger.error(
                "unhandled job exception",
                extra={
                    "job_id": job.id,
                    "audit_id": job.audit_id,
                    "worker_id": self.worker_id,
                    "exception_type": type(exc).__name__,
                    "traceback": traceback.format_exc(),
                },
            )
            current = self.service.get_job(job.id)
            if token.cancelled or current.cancel_requested:
                self.service.cancel_running_job(job.id)
            else:
                self.service.fail_job(
                    job.id,
                    JobError(
                        code="unhandled_exception",
                        category=ErrorCategory.INTERNAL,
                        message="Job failed due to an internal error",
                        component="job_worker",
                        retryable=False,
                        details={"exception_type": type(exc).__name__},
                    ),
                )
        finally:
            monitor_stop.set()
            monitor.join(timeout=2)
            self.service.heartbeat_worker(self.worker_id, status="idle")

        final = self.service.get_job(job.id)
        self.logger.info(
            "job execution finished",
            extra={
                "job_id": job.id,
                "audit_id": job.audit_id,
                "job_status": final.status.value,
                "worker_id": self.worker_id,
            },
        )
    def run_forever(self, stop_event: threading.Event) -> None:
        self.startup()
        while not stop_event.is_set():
            handled = self.run_once()
            if not handled:
                stop_event.wait(self.settings.worker_poll_interval_seconds)
        self.service.heartbeat_worker(self.worker_id, status="stopped")

    def _monitor_cancellation(
        self,
        job_id: str,
        token: CancellationToken,
        stop_event: threading.Event,
    ) -> None:
        interval = min(
            0.25,
            self.settings.worker_poll_interval_seconds,
        )
        while not stop_event.wait(interval):
            try:
                job = self.service.get_job(job_id)
            except Exception:
                continue
            if job.cancel_requested or job.status.terminal:
                token.cancel()
                return


class WorkerSupervisor:
    def __init__(
        self,
        *,
        service: JobService,
        registry: HandlerRegistry,
        evidence_store: EvidenceStore,
        settings: Settings,
    ) -> None:
        self.service = service
        self.registry = registry
        self.evidence_store = evidence_store
        self.settings = settings
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.supervisor_id = f"{socket.gethostname()}:{os.getpid()}:supervisor"

    def start(self) -> int:
        interrupted = self.service.prepare_supervisor(
            self.supervisor_id,
            stale_after_seconds=self.settings.worker_stale_after_seconds,
        )
        MaintenanceService(
            self.service.database,
            self.evidence_store,
            self.settings,
        ).run_startup_cleanup()
        prefix = f"{socket.gethostname()}:{os.getpid()}"
        for index in range(self.settings.worker_concurrency):
            worker = JobWorker(
                worker_id=f"{prefix}:{index}",
                service=self.service,
                registry=self.registry,
                evidence_store=self.evidence_store,
                settings=self.settings,
            )
            thread = threading.Thread(
                target=worker.run_forever,
                args=(self.stop_event,),
                name=f"wirescope-worker-{index}",
                daemon=False,
            )
            thread.start()
            self.threads.append(thread)
        return interrupted

    def stop(self, timeout_seconds: float = 10) -> None:
        self.stop_event.set()
        deadline = time.monotonic() + timeout_seconds
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        self.service.heartbeat_worker(
            self.supervisor_id,
            status="stopped",
        )


def build_registry() -> HandlerRegistry:
    registry = HandlerRegistry()
    registry.register("passive_discovery", PassiveDiscoveryHandler())
    registry.register("active_discovery", ActiveDiscoveryHandler())
    registry.register("protocol_audit", ProtocolAuditHandler())
    registry.register("findings_evaluation", FindingsEvaluationHandler())
    registry.register("report_generation", ReportGenerationHandler())
    return registry


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("WireScope worker must not run as root")
    settings = get_settings()
    database = Database(settings)
    service = JobService(database)
    evidence_store = EvidenceStore(database, settings)
    supervisor = WorkerSupervisor(
        service=service,
        registry=build_registry(),
        evidence_store=evidence_store,
        settings=settings,
    )

    def request_stop(_signum: int, _frame: Any) -> None:
        supervisor.stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    supervisor.start()
    for thread in supervisor.threads:
        thread.join()
    service.heartbeat_worker(
        supervisor.supervisor_id,
        status="stopped",
    )


if __name__ == "__main__":
    main()
