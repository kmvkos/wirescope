from backend.ssh_credentials import SshCredentialReferenceError, SshCredentialSpool
from engine.scope import ActiveProfile, ScopeValidator
from jobs.worker import build_registry
from tests.helpers import http_request as request


def _create_confirmed_ssh_audit(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    scope = ScopeValidator(app.state.settings).validate(
        ["192.0.2.0/24"],
        ActiveProfile.STANDARD,
    )
    confirmed = app.state.inventory.confirm_scope(
        audit_id=audit.id,
        scope=scope,
        interface="eth0",
        route_context={
            "interface": "eth0",
            "routes": [
                {
                    "target": "192.0.2.0/24",
                    "representative_address": "192.0.2.1",
                    "family": 4,
                    "interface": "eth0",
                    "source_address": "192.0.2.10",
                    "gateway": None,
                    "directly_connected": True,
                }
            ],
        },
        actor="auditor",
        timing_policy="T3",
    )
    return app, service, audit, confirmed


def _payload(target="192.0.2.1"):
    return {
        "target": target,
        "username": "wirescope-ro",
        "port": 22,
        "authentication": "private_key",
        "private_key": "temporary-private-key-material",
        "known_hosts": f"{target} ssh-ed25519 AAAATESTHOSTKEY",
    }


def test_ssh_credential_spool_is_0600_and_reference_safe(durable_settings):
    spool = SshCredentialSpool(durable_settings)
    reference = spool.put(
        {
            "username": "audit",
            "private_key": "temporary-secret-key",
            "known_hosts": "192.0.2.1 ssh-ed25519 AAAA",
        }
    )
    path = spool._path(reference)
    assert len(reference) == 32
    assert "secret" not in reference
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert spool.consume(reference)["private_key"] == "temporary-secret-key"
    spool.delete(reference)
    assert not path.exists()
    try:
        spool.consume(reference)
    except SshCredentialReferenceError:
        pass
    else:
        raise AssertionError("deleted SSH credential reference must not be readable")


def test_ssh_topology_api_requires_confirmed_scope(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/ssh",
        json=_payload(),
        as_role="auditor",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "ssh_scope_required"


def test_ssh_topology_api_is_auditor_only_and_target_must_be_in_scope(api_context):
    app, _service, audit, _confirmed = _create_confirmed_ssh_audit(api_context)

    viewer = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/ssh",
        json=_payload(),
        as_role="viewer",
    )
    assert viewer.status_code == 403

    outside = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/ssh",
        json=_payload("198.51.100.1"),
        as_role="auditor",
    )
    assert outside.status_code == 422
    assert outside.json()["detail"]["code"] == "ssh_target_out_of_scope"


def test_ssh_topology_job_persists_no_secret_cancel_removes_spool_and_retry_requires_fresh_credentials(api_context):
    app, service, audit, confirmed = _create_confirmed_ssh_audit(api_context)
    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/ssh",
        json=_payload(),
        as_role="auditor",
    )
    assert response.status_code == 202, response.text
    job = service.get_job(response.json()["job_id"])
    assert job.type == "ssh_topology"
    assert job.parameters["confirmed_scope_id"] == confirmed.id
    serialized = repr(job.parameters)
    assert "temporary-private-key-material" not in serialized
    assert "AAAATESTHOSTKEY" not in serialized
    assert job.parameters["credential_profile"] == {
        "username": "wirescope-ro",
        "port": 22,
        "authentication": "private_key",
        "host_key_verification": "strict",
    }

    spool = SshCredentialSpool(app.state.settings)
    path = spool._path(job.parameters["credential_ref"])
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600

    cancelled = request(
        app,
        "POST",
        f"/api/v1/jobs/{job.id}/cancel",
        as_role="auditor",
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert not path.exists()

    retry = request(
        app,
        "POST",
        f"/api/v1/jobs/{job.id}/retry",
        as_role="auditor",
    )
    assert retry.status_code == 409
    assert "fresh credentials" in retry.json()["detail"]["message"]


def test_worker_registry_and_root_assets_include_ssh_topology(api_context):
    app, _service, _evidence, _environment = api_context
    assert "ssh_topology" in build_registry().job_types
    response = request(app, "GET", "/", as_role="viewer")
    assert response.status_code == 200
    body = response.text
    assert body.count("ssh_topology.css?v=20260826-ui18") == 1
    assert body.count("ssh_topology.js?v=20260826-ui18") == 1
    assert body.index("snmp_topology.js?v=20260825-ui14") < body.index("ssh_topology.js?v=20260826-ui18")
    assert body.index("ssh_topology.js?v=20260826-ui18") < body.index("topology_tab.js?v=20260825-ui14")
