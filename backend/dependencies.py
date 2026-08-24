from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request

from auth.service import AuthService
from config.settings import Settings
from engine.interfaces import InterfaceService
from engine.network import NetworkService
from engine.routes import RouteResolver
from findings.store import FindingStore
from inventory.service import InventoryService
from jobs.service import JobService
from persistence.database import Database
from protocol_audits.registry import ModuleRegistry
from protocol_audits.store import ProtocolObservationStore
from reports.store import ReportStore
from storage.evidence import EvidenceStore


@dataclass(frozen=True)
class AppServices:
    settings: Settings
    database: Database
    jobs: JobService
    evidence: EvidenceStore
    interfaces: InterfaceService
    routes: RouteResolver
    inventory: InventoryService
    observations: ProtocolObservationStore
    findings: FindingStore
    reports: ReportStore
    auth: AuthService
    network: NetworkService
    environment_provider: Callable[[], dict[str, Any]]
    module_registry: ModuleRegistry


def get_services(request: Request) -> AppServices:
    return request.app.state.services
