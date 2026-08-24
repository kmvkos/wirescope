"""Defined appliance recovery after reboot or process restart."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryPolicy:
    running_jobs: str
    queued_jobs: str
    cancelled_running: str
    kiosk_restart: str
    api_restart: str
    worker_restart: str
    automatic_retry: bool


APPLIANCE_RECOVERY = RecoveryPolicy(
    running_jobs="interrupted with code application_restart",
    queued_jobs="remain queued and eligible for the recovered worker",
    cancelled_running="stay cancelled; cancellation is durable",
    kiosk_restart="reload the local browser only; audits keep running",
    api_restart="does not terminate worker jobs",
    worker_restart="recovers running jobs as interrupted, then claims queued work",
    automatic_retry=False,
)


def describe_reboot_recovery() -> dict[str, object]:
    policy = APPLIANCE_RECOVERY
    return {
        "running": policy.running_jobs,
        "queued": policy.queued_jobs,
        "kiosk": policy.kiosk_restart,
        "automatic_retry": policy.automatic_retry,
        "error_code": "application_restart",
    }
