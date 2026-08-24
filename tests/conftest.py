from dataclasses import replace
from types import SimpleNamespace

import pytest

from backend.app import create_app
from config.settings import get_settings
from engine.interfaces import (
    InterfaceInfo,
    InterfaceValidationCode,
    InterfaceValidationError,
)
from engine.routes import ResolvedScope, TargetRoute
from jobs.service import JobService
from persistence.database import Database
from persistence.schema import apply_migrations
from storage.evidence import EvidenceStore
from tests.helpers import login_role


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
        bootstrap_auditor_username="auditor",
        bootstrap_auditor_password="auditor-pass",
        bootstrap_viewer_username="viewer",
        bootstrap_viewer_password="viewer-pass",
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


class _RouteStub:
    def resolve(self, interface_name, scope):
        return ResolvedScope(
            interface=interface_name,
            interface_state="UP",
            vlan_subinterface="." in interface_name,
            routes=[
                TargetRoute(
                    target=target.value,
                    representative_address=target.value.split("/", 1)[0],
                    family=target.family,
                    interface=interface_name,
                    source_address=(
                        "192.0.2.10"
                        if target.family == 4
                        else "2001:db8::10"
                    ),
                    gateway=None,
                    directly_connected=True,
                )
                for target in scope.targets
            ],
        )


class _InterfaceStub:
    def __init__(self):
        self.interface = InterfaceInfo(
            name="eth0",
            state="UP",
            mac="00:11:22:33:44:55",
            mtu=1500,
            ipv4=["192.0.2.10/24"],
            allowed=True,
        )

    def validate(self, name):
        if name != self.interface.name:
            raise InterfaceValidationError(
                InterfaceValidationCode.UNKNOWN_INTERFACE,
                f"Unknown network interface: {name}",
            )
        return self.interface

    def discover(self):
        return SimpleNamespace(interfaces=[self.interface])


@pytest.fixture
def api_context(
    durable_settings,
    database,
    job_service,
    evidence_store,
):
    settings = replace(
        durable_settings,
        dumpcap_binary="/bin/true",
        tshark_binary="/bin/true",
        nmap_binary="/bin/true",
    )
    environment = {
        "hostname": "wirescope-test",
        "interfaces": [
            {
                "name": "eth0",
                "state": "UP",
                "mac": "00:11:22:33:44:55",
                "mtu": 1500,
                "ipv4": ["192.0.2.10/24"],
            }
        ],
        "default_route": {"gateway": "192.0.2.1"},
        "routes": [],
        "dns": ["192.0.2.53"],
    }
    app = create_app(
        settings=settings,
        database=database,
        job_service=job_service,
        evidence_store=evidence_store,
        interface_service=_InterfaceStub(),
        route_resolver=_RouteStub(),
        environment_provider=lambda: environment,
    )
    app.state.auth_cookies = {
        "auditor": login_role(app, "auditor", "auditor-pass"),
        "viewer": login_role(app, "viewer", "viewer-pass"),
    }
    return app, job_service, evidence_store, environment
