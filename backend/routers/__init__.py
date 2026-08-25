from fastapi import APIRouter

from . import (
    audits,
    auth,
    captures,
    findings,
    insights,
    inventory,
    jobs,
    operations,
    protocol,
    reports,
    system,
    traffic,
)


api_router = APIRouter()
for router in (
    auth.router,
    system.router,
    insights.router,
    operations.router,
    audits.router,
    captures.router,
    traffic.router,
    inventory.router,
    protocol.router,
    findings.router,
    reports.router,
    jobs.router,
):
    api_router.include_router(router)
