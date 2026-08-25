from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.snmp_credentials import CredentialReferenceError, SnmpCredentialSpool
from engine.scope import ActiveProfile, ScopeValidator
from jobs.models import RetentionClass
from jobs.worker import build_registry
from providers.snmp_topology import (
    DOT1D_BASE_PORT_IFINDEX,
    DOT1Q_FDB_ENTRY,
    DOT1Q_PVID,
    DOT1Q_VLAN_CURRENT_ENTRY,
    IF_DESCR,
    IF_NAME,
    IP_NET_TO_MEDIA_PHYS,
    LLDP_LOC_PORT_ENTRY,
    LLDP_REM_ENTRY,
    SnmpCredentialError,
    _credential_args,
    _parse_output,
    normalize_topology_collections,
    sanitize_credential_profile,
)
from tests.helpers import http_request as request
from topology.snmp import decorate_snmp_topology


def _v3_credentials():
    return {
        "version": "3",
        "username": "wirescope-ro",
        "security_level": "authPriv",
        "auth_protocol": "SHA",
        "auth_password": "auth-secret",
        "priv_protocol": "AES",
        "priv_password": "priv-secret",
    }


def test_snmp_credential_spool_is_0600_consume_once_and_validates_refs(durable_settings):
    spool = SnmpCredentialSpool(durable_settings)
    reference = spool.put(_v3_credentials())
    assert len(reference) == 32
    assert "secret" not in reference
    path = spool._path(reference)
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert spool.consume(reference)["auth_password"] == "auth-secret"
    spool.delete(reference)
    assert not path.exists()
    with pytest.raises(CredentialReferenceError):
        spool.consume(reference)
    with pytest.raises(CredentialReferenceError):
        spool.delete("../../unsafe")


def test_snmp_credential_profile_never_exposes_secrets_and_rejects_v1():
    profile = sanitize_credential_profile(_v3_credentials())
    assert profile == {
        "version": "3",
        "security_level": "authPriv",
        "username": "wirescope-ro",
        "auth_protocol": "SHA",
        "priv_protocol": "AES",
    }
    assert "auth-secret" not in repr(profile)
    assert "priv-secret" not in repr(profile)
    with pytest.raises(SnmpCredentialError):
        sanitize_credential_profile({"version": "1", "community": "public"})
    with pytest.raises(SnmpCredentialError):
        sanitize_credential_profile({"version": "2c"})


def test_snmp_command_marks_community_and_v3_passwords_sensitive():
    v2_args, v2_sensitive = _credential_args({"version": "2c", "community": "private-ro"})
    assert v2_args[v2_args.index("-c") + 1] == "private-ro"
    assert v2_args.index("private-ro") in v2_sensitive

    v3_args, v3_sensitive = _credential_args(_v3_credentials())
    assert v3_args.index("auth-secret") in v3_sensitive
    assert v3_args.index("priv-secret") in v3_sensitive
    assert v3_args.index("wirescope-ro") not in v3_sensitive


def test_net_snmp_numeric_parser_and_qbridge_normalization_map_mac_to_port_vlan_and_lldp():
    parsed = _parse_output(
        ".1.3.6.1.2.1.17.7.1.2.2.1.1.10.0.17.34.51.68.85 = Hex-STRING: 00 11 22 33 44 55\n"
        ".1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.17.34.51.68.85 = INTEGER: 5\n",
        max_rows=10,
    )
    assert parsed[0]["value"]["hex"] == "001122334455"
    assert parsed[1]["value"] == 5

    collections = {
        "if_descr": [
            {"oid": f"{IF_DESCR}.101", "value": "GigabitEthernet1/0/5"},
        ],
        "if_name": [
            {"oid": f"{IF_NAME}.101", "value": "Gi1/0/5"},
        ],
        "if_alias": [],
        "if_admin": [],
        "if_oper": [],
        "bridge_ports": [
            {"oid": f"{DOT1D_BASE_PORT_IFINDEX}.5", "value": 101},
        ],
        "pvid": [
            {"oid": f"{DOT1Q_PVID}.5", "value": 10},
        ],
        "vlan_current": [
            {"oid": f"{DOT1Q_VLAN_CURRENT_ENTRY}.3.0.10", "value": 10},
            {"oid": f"{DOT1Q_VLAN_CURRENT_ENTRY}.4.0.10", "value": {"octets": [8]}},
        ],
        "vlan_static": [],
        "dot1q_fdb": [
            {
                "oid": f"{DOT1Q_FDB_ENTRY}.1.10.0.17.34.51.68.85",
                "value": {"octets": [0, 17, 34, 51, 68, 85]},
            },
            {"oid": f"{DOT1Q_FDB_ENTRY}.2.10.0.17.34.51.68.85", "value": 5},
            {"oid": f"{DOT1Q_FDB_ENTRY}.3.10.0.17.34.51.68.85", "value": 3},
        ],
        "dot1d_fdb": [],
        "arp": [
            {
                "oid": f"{IP_NET_TO_MEDIA_PHYS}.101.192.0.2.10",
                "value": {"octets": [0, 17, 34, 51, 68, 85]},
            }
        ],
        "lldp_local": [
            {"oid": f"{LLDP_LOC_PORT_ENTRY}.3.5", "value": "Gi1/0/5"},
            {"oid": f"{LLDP_LOC_PORT_ENTRY}.4.5", "value": "Server access"},
        ],
        "lldp_remote": [
            {
                "oid": f"{LLDP_REM_ENTRY}.5.123.5.1",
                "value": {"octets": [170, 187, 204, 221, 238, 255]},
            },
            {"oid": f"{LLDP_REM_ENTRY}.7.123.5.1", "value": "Ethernet1"},
            {"oid": f"{LLDP_REM_ENTRY}.9.123.5.1", "value": "access-01"},
        ],
    }
    result = normalize_topology_collections(collections)
    assert result["interfaces"][0]["ifindex"] == 101
    assert result["interfaces"][0]["name"] == "Gi1/0/5"
    assert result["interfaces"][0]["bridge_port"] == 5
    assert result["interfaces"][0]["pvid"] == 10
    assert result["interfaces"][0]["vlan_ids"] == [10]
    assert result["fdb"][0]["mac"] == "00:11:22:33:44:55"
    assert result["fdb"][0]["ifindex"] == 101
    assert result["fdb"][0]["interface_name"] == "Gi1/0/5"
    assert result["fdb"][0]["vlan_ids"] == [10]
    assert result["arp"] == [
        {
            "ip": "192.0.2.10",
            "mac": "00:11:22:33:44:55",
            "ifindex": 101,
            "interface_name": "Gi1/0/5",
        }
    ]
    assert result["lldp_neighbors"][0]["local_interface_name"] == "Gi1/0/5"
    assert result["lldp_neighbors"][0]["remote_chassis_id"] == "aa:bb:cc:dd:ee:ff"
    assert result["lldp_neighbors"][0]["remote_system_name"] == "access-01"


def test_persisted_snmp_evidence_decorates_switch_port_vlan_and_lldp(
    durable_settings,
    job_service,
    evidence_store,
    database,
):
    audit = job_service.create_audit(
        profile="deep",
        interface="eth0",
        scope={},
        actor="auditor",
    )
    document = {
        "schema": "snmp-topology-result",
        "schema_version": 1,
        "status": "completed",
        "target": "192.0.2.1",
        "interface": "eth0",
        "credential_profile": {"version": "3", "security_level": "authPriv", "username": "ro"},
        "system": {"name": "core-sw", "description": "Example switch"},
        "interfaces": [
            {"ifindex": 101, "name": "Gi1/0/5", "bridge_port": 5, "pvid": 10, "vlan_ids": [10]},
        ],
        "fdb": [
            {
                "mac": "00:11:22:33:44:55",
                "bridge_port": 5,
                "ifindex": 101,
                "interface_name": "Gi1/0/5",
                "vlan_ids": [10],
                "source": "q-bridge-fdb",
            }
        ],
        "arp": [{"ip": "192.0.2.10", "mac": "00:11:22:33:44:55", "ifindex": 101}],
        "lldp_neighbors": [
            {
                "local_interface_name": "Gi1/0/24",
                "remote_chassis_id": "aa:bb:cc:dd:ee:ff",
                "remote_port_id": "Gi0/1",
                "remote_system_name": "access-sw",
            }
        ],
        "vlans": [{"vlan_id": 10, "name": "users", "fdb_id": 10}],
        "warnings": [],
    }
    artifact = evidence_store.put_json(
        audit_id=audit.id,
        job_id=None,
        artifact_type="snmp_topology_result",
        document=document,
        retention_class=RetentionClass.AUDIT,
        schema_name="snmp-topology-result",
        schema_version=1,
    )
    topology = {
        "nodes": [
            {
                "id": "asset:switch",
                "kind": "asset",
                "label": "192.0.2.1",
                "roles": ["network-device"],
                "addresses": ["192.0.2.1"],
                "names": [],
                "mac": "00:aa:00:aa:00:aa",
                "segment_ids": ["segment:192.0.2.0/24"],
                "confidence": "observed",
                "provenance": ["nmap"],
            },
            {
                "id": "asset:server",
                "kind": "asset",
                "label": "server01",
                "roles": [],
                "addresses": ["192.0.2.10"],
                "names": ["server01"],
                "mac": "00:11:22:33:44:55",
                "segment_ids": ["segment:192.0.2.0/24"],
                "confidence": "observed",
                "provenance": ["nmap"],
            },
        ],
        "edges": [],
        "warnings": [],
        "summary": {},
    }
    services = SimpleNamespace(database=database, jobs=job_service, evidence=evidence_store)
    result = decorate_snmp_topology(services, audit.id, topology)
    assert artifact.id in result["snmp_topology"]["artifact_ids"]
    assert result["snmp_topology"]["devices"] == 1
    port_edges = [edge for edge in result["edges"] if edge.get("mapping_type") == "switch_port"]
    assert len(port_edges) == 1
    assert port_edges[0]["source"] == "asset:switch"
    assert port_edges[0]["target"] == "asset:server"
    assert port_edges[0]["relation"] == "layer2_neighbor"
    assert "Gi1/0/5" in port_edges[0]["port_id"]
    assert "PVID 10" in port_edges[0]["port_id"]
    assert "VLAN 10" in port_edges[0]["port_id"]
    server = next(node for node in result["nodes"] if node["id"] == "asset:server")
    assert server["vlan_ids"] == [10]
    lldp_edges = [edge for edge in result["edges"] if edge.get("mapping_type") == "snmp_lldp_neighbor"]
    assert len(lldp_edges) == 1
    assert lldp_edges[0]["local_port"] == "Gi1/0/24"
    assert lldp_edges[0]["remote_port"] == "Gi0/1"
    assert any(node.get("label") == "access-sw" for node in result["nodes"])


def _create_confirmed_snmp_audit(api_context):
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


def test_snmp_topology_api_requires_confirmed_scope(api_context):
    app, service, _evidence, _environment = api_context
    audit = service.create_audit(profile="deep", interface="eth0", scope={}, actor="auditor")
    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/snmp",
        json={"target": "192.0.2.1", "version": "2c", "community": "private-ro"},
        as_role="auditor",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "snmp_scope_required"


def test_snmp_topology_api_is_auditor_only_and_target_must_be_in_confirmed_scope(api_context):
    app, _service, audit, _confirmed = _create_confirmed_snmp_audit(api_context)
    payload = {"target": "192.0.2.1", "version": "2c", "community": "private-ro"}
    viewer = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/snmp",
        json=payload,
        as_role="viewer",
    )
    assert viewer.status_code == 403

    outside = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/snmp",
        json={**payload, "target": "198.51.100.1"},
        as_role="auditor",
    )
    assert outside.status_code == 422
    assert outside.json()["detail"]["code"] == "snmp_target_out_of_scope"


def test_snmp_topology_job_persists_no_secret_cancel_removes_spool_and_retry_requires_fresh_credentials(api_context):
    app, service, audit, confirmed = _create_confirmed_snmp_audit(api_context)
    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/topology/snmp",
        json={
            "target": "192.0.2.1",
            "version": "3",
            "username": "wirescope-ro",
            "security_level": "authPriv",
            "auth_protocol": "SHA",
            "auth_password": "auth-secret",
            "priv_protocol": "AES",
            "priv_password": "priv-secret",
        },
        as_role="auditor",
    )
    assert response.status_code == 202, response.text
    job = service.get_job(response.json()["job_id"])
    assert job.type == "snmp_topology"
    assert job.parameters["confirmed_scope_id"] == confirmed.id
    serialized = repr(job.parameters)
    assert "auth-secret" not in serialized
    assert "priv-secret" not in serialized
    assert "credential_ref" in job.parameters
    assert job.parameters["credential_profile"]["username"] == "wirescope-ro"

    spool = SnmpCredentialSpool(app.state.settings)
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


def test_worker_registry_and_root_assets_include_snmp_topology(api_context):
    app, _service, _evidence, _environment = api_context
    assert "snmp_topology" in build_registry().job_types
    response = request(app, "GET", "/", as_role="viewer")
    assert response.status_code == 200
    body = response.text
    assert body.count("snmp_topology.css?v=20260825-ui14") == 1
    assert body.count("snmp_topology.js?v=20260825-ui14") == 1
    assert body.index("topology.js?v=20260825-ui14") < body.index("snmp_topology.js?v=20260825-ui14")
    assert body.index("snmp_topology.js?v=20260825-ui14") < body.index("topology_tab.js?v=20260825-ui14")


def test_snmp_topology_frontend_uses_canonical_api_and_has_kiosk_layout(durable_settings):
    javascript = (durable_settings.frontend_dir / "snmp_topology.js").read_text(encoding="utf-8")
    css = (durable_settings.frontend_dir / "snmp_topology.css").read_text(encoding="utf-8")
    assert 'const API = "/api/v1"' in javascript
    assert "/topology/snmp" in javascript
    assert "authPriv" in javascript
    assert "SNMPv2c community" in javascript
    assert "@media (max-width: 560px)" in css
