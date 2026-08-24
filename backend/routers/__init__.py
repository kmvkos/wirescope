from fastapi import APIRouter

from . import (
    audits,
    auth,
    captures,
    findings,
    inventory,
    jobs,
    protocol,
    reports,
    system,
)


api_router = APIRouter()
for router in (
    auth.router,
    system.router,
    audits.router,
    captures.router,
    inventory.router,
    protocol.router,
    findings.router,
    reports.router,
    jobs.router,
):
    api_router.include_router(router)
