from datetime import datetime, timezone

from findings.engine import deduplicate_drafts, evaluate_findings
from findings.models import EvaluationContext, FindingDraft, Severity
from findings.registry import default_registry
from tests.helpers import sample_observation, sample_service


def _context(
    observations=None,
    services=None,
    evaluated_at=None,
    passive_result=None,
    passive_artifact_id=None,
) -> EvaluationContext:
    return EvaluationContext(
        audit_id="audit-1",
        observations=observations or [],
        services=services or [],
        assets=[],
        passive_result=passive_result,
        passive_artifact_id=passive_artifact_id,
        evaluated_at=evaluated_at or datetime(2026, 8, 24, tzinfo=timezone.utc),
    )


def _ids(drafts: list[FindingDraft]) -> set[str]:
    return {item.rule_id for item in drafts}


def test_default_registry_is_independent_of_scanners():
    registry = default_registry()
    assert "WS-SSH-WEAK-ALGORITHMS" in registry.rule_ids
    assert len(registry.rule_ids) >= 15


def test_weak_ssh_algorithms_and_modern_ssh_false_positive():
    weak = sample_observation(
        data={
            "kex": ["diffie-hellman-group1-sha1", "curve25519-sha256"],
            "host_key": ["ssh-rsa"],
            "encryption": ["aes256-cbc", "chacha20-poly1305@openssh.com"],
            "mac": ["hmac-sha2-256"],
        }
    )
    modern = sample_observation(
        observation_id="obs-modern",
        data={
            "kex": ["curve25519-sha256"],
            "host_key": ["rsa-sha2-512", "ssh-ed25519"],
            "encryption": ["chacha20-poly1305@openssh.com"],
            "mac": ["hmac-sha2-256"],
        },
    )
    findings = evaluate_findings(_context([weak]))
    assert "WS-SSH-WEAK-ALGORITHMS" in _ids(findings)
    ssh = next(item for item in findings if item.rule_id == "WS-SSH-WEAK-ALGORITHMS")
    assert ssh.severity == Severity.HIGH
    assert ssh.observation_ids == [weak.id]
    assert ssh.evidence_artifact_ids == ["evidence-1"]
    assert evaluate_findings(_context([modern])) == []


def test_tool_unavailable_is_not_a_security_finding():
    missing = sample_observation(
        kind="tool_unavailable",
        data={"tool": "ssh-audit", "message": "missing"},
        source="ssh-audit",
    )
    timeout = sample_observation(
        observation_id="obs-timeout",
        kind="tool_timeout",
        data={"tool": "openssl"},
        protocol="tls",
        module="tls",
        source="openssl",
    )
    assert evaluate_findings(_context([missing, timeout])) == []


def test_tls_legacy_cipher_expiry_and_modern_false_positive():
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    legacy = [
        sample_observation(
            kind="tls_session",
            protocol="tls",
            module="tls",
            source="openssl",
            data={"protocol": "TLSv1.0", "cipher": "AES128-SHA"},
        ),
        sample_observation(
            observation_id="obs-cert",
            kind="tls_certificate",
            protocol="tls",
            module="tls",
            source="openssl",
            data={
                "subject": "CN=old",
                "not_after": "Jan 1 00:00:00 2024 GMT",
                "verify_code": 18,
                "verify_message": "self signed certificate",
            },
        ),
    ]
    modern = [
        sample_observation(
            kind="tls_session",
            protocol="tls",
            module="tls",
            source="openssl",
            data={"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
        ),
        sample_observation(
            observation_id="obs-cert-ok",
            kind="tls_certificate",
            protocol="tls",
            module="tls",
            source="openssl",
            data={
                "subject": "CN=ok",
                "not_after": "Jan 1 00:00:00 2027 GMT",
                "verify_code": 0,
                "verify_message": "ok",
            },
        ),
    ]
    findings = evaluate_findings(_context(legacy, evaluated_at=now))
    assert {
        "WS-TLS-LEGACY-PROTOCOL",
        "WS-TLS-CERT-EXPIRED",
        "WS-TLS-CERT-UNTRUSTED",
    } <= _ids(findings)
    assert "WS-TLS-WEAK-CIPHER" not in _ids(findings)
    assert evaluate_findings(_context(modern, evaluated_at=now)) == []


def test_weak_tls_cipher_and_unparseable_dates_are_not_expired():
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    weak = sample_observation(
        kind="tls_session",
        protocol="tls",
        module="tls",
        source="openssl",
        data={"protocol": "TLSv1.2", "cipher": "TLS_RSA_WITH_RC4_128_SHA"},
    )
    junk_date = sample_observation(
        observation_id="obs-cert",
        kind="tls_certificate",
        protocol="tls",
        module="tls",
        source="openssl",
        data={"not_after": "not a date", "verify_code": 0},
    )
    findings = evaluate_findings(_context([weak, junk_date], evaluated_at=now))
    assert _ids(findings) == {"WS-TLS-WEAK-CIPHER"}


def test_http_hsts_only_on_https_and_missing_headers():
    http = sample_service(port=80, name="http", service_id="svc-http")
    https = sample_service(
        port=443,
        name="https",
        tunnel="ssl",
        service_id="svc-https",
    )
    plain = sample_observation(
        kind="http_response",
        protocol="http",
        module="http",
        source="curl",
        service_id="svc-http",
        data={
            "status_code": 200,
            "headers": {"server": "nginx/1.22.1", "x-frame-options": "SAMEORIGIN"},
        },
    )
    secure = sample_observation(
        observation_id="obs-https",
        kind="http_response",
        protocol="http",
        module="http",
        source="curl",
        service_id="svc-https",
        data={"status_code": 200, "headers": {"server": "nginx"}},
    )
    findings = evaluate_findings(
        _context([plain, secure], services=[http, https])
    )
    assert "WS-HTTP-MISSING-HSTS" in _ids(findings)
    hsts = next(item for item in findings if item.rule_id == "WS-HTTP-MISSING-HSTS")
    assert hsts.service_id == "svc-https"
    assert "WS-HTTP-SERVER-DISCLOSURE" in _ids(findings)
    assert "WS-HTTP-MISSING-SECURITY-HEADERS" in _ids(findings)
    assert not any(
        item.rule_id == "WS-HTTP-MISSING-HSTS" and item.service_id == "svc-http"
        for item in findings
    )


def test_smb_dns_snmp_ldap_false_positive_boundaries():
    denied = sample_observation(
        kind="smb_null_session",
        protocol="smb",
        module="smb",
        source="smbclient",
        data={"accepted": False, "status": "NT_STATUS_ACCESS_DENIED"},
    )
    silent_snmp = sample_observation(
        observation_id="obs-snmp",
        kind="snmp_unauthenticated",
        protocol="snmp",
        module="snmp",
        source="snmpget",
        data={"responded": False, "auth": "none", "version": "3"},
    )
    refused_ldap = sample_observation(
        observation_id="obs-ldap",
        kind="ldap_anonymous_bind",
        protocol="ldap",
        module="ldap",
        source="ldapsearch",
        data={"anonymous_bind": False, "status": "Invalid credentials"},
    )
    no_recursion = sample_observation(
        observation_id="obs-dns",
        kind="dns_flags",
        protocol="dns",
        module="dns",
        source="dig",
        data={"flags": ["qr", "aa"], "recursion_available": False},
    )
    assert (
        evaluate_findings(_context([denied, silent_snmp, refused_ldap, no_recursion]))
        == []
    )


def test_positive_smb_snmp_ldap_dns_and_signing_only_when_fields_exist():
    accepted = sample_observation(
        kind="smb_null_session",
        protocol="smb",
        module="smb",
        source="smbclient",
        data={"accepted": True, "share_count": 2, "shares": [{"name": "IPC$"}]},
    )
    unsigned = sample_observation(
        observation_id="obs-sign",
        kind="smb_null_session",
        protocol="smb",
        module="smb",
        source="smbclient",
        service_id="svc-smb2",
        asset_id="asset-2",
        data={"accepted": False, "signing": "disabled"},
    )
    snmp = sample_observation(
        observation_id="obs-snmp",
        kind="snmp_unauthenticated",
        protocol="snmp",
        module="snmp",
        source="snmpget",
        data={"responded": True, "auth": "none", "version": "3", "usm_indicator": "Unknown user name"},
    )
    ldap = sample_observation(
        observation_id="obs-ldap",
        kind="ldap_rootdse",
        protocol="ldap",
        module="ldap",
        source="ldapsearch",
        data={"anonymous_bind": True, "attributes": {"namingcontexts": ["DC=example"]}},
    )
    dns = sample_observation(
        observation_id="obs-dns",
        kind="dns_flags",
        protocol="dns",
        module="dns",
        source="dig",
        data={"flags": ["qr", "aa", "ra"], "recursion_available": True},
    )
    identity = sample_observation(
        observation_id="obs-id",
        kind="dns_identity",
        protocol="dns",
        module="dns",
        source="dig",
        data={"version": "BIND 9.18.12"},
    )
    findings = evaluate_findings(
        _context([accepted, unsigned, snmp, ldap, dns, identity])
    )
    assert {
        "WS-SMB-NULL-SESSION",
        "WS-SMB-SIGNING-DISABLED",
        "WS-SNMP-UNAUTHENTICATED",
        "WS-LDAP-ANONYMOUS-BIND",
        "WS-DNS-RECURSION",
        "WS-DNS-VERSION-DISCLOSED",
    } <= _ids(findings)
    assert "WS-SMB-LEGACY-DIALECT" not in _ids(findings)


def test_insecure_management_from_inventory_not_from_open_ssh():
    ftp = sample_service(port=21, name="ftp", product="vsftpd", service_id="svc-ftp")
    ssh = sample_service(port=22, name="ssh", service_id="svc-ssh")
    closed = sample_service(
        port=23,
        name="telnet",
        state="closed",
        service_id="svc-telnet",
    )
    findings = evaluate_findings(_context(services=[ftp, ssh, closed]))
    assert _ids(findings) == {"WS-MGMT-INSECURE-PROTOCOL"}
    assert findings[0].service_id == "svc-ftp"
    assert findings[0].severity == Severity.HIGH


def test_infrastructure_from_passive_assessment_not_from_errors():
    detected = {
        "result": {
            "sensors": {
                "llmnr": {"status": "detected", "hits": 3},
                "nbns": {"status": "error", "hits": 0, "errors": ["decode"]},
                "dhcpv4": {
                    "status": "detected",
                    "hits": 2,
                    "summary": {
                        "servers": [
                            {"server_id": "192.0.2.1"},
                            {"server_id": "192.0.2.2"},
                        ]
                    },
                },
            }
        }
    }
    findings = evaluate_findings(
        _context(passive_result=detected, passive_artifact_id="passive-1")
    )
    assert {
        "WS-INFRA-LLMNR",
        "WS-INFRA-MULTIPLE-DHCP",
    } <= _ids(findings)
    assert "WS-INFRA-NBNS" not in _ids(findings)
    llmnr = next(item for item in findings if item.rule_id == "WS-INFRA-LLMNR")
    assert llmnr.evidence_artifact_ids == ["passive-1"]
    assert llmnr.asset_id is None


def test_correlation_and_deduplication_across_observations():
    first = sample_observation(
        data={
            "kex": ["diffie-hellman-group14-sha1"],
            "host_key": [],
            "encryption": [],
            "mac": [],
        }
    )
    second = sample_observation(
        observation_id="obs-2",
        evidence_artifact_id="evidence-2",
        data={
            "kex": ["diffie-hellman-group1-sha1"],
            "host_key": [],
            "encryption": [],
            "mac": [],
        },
    )
    drafts = evaluate_findings(_context([first, second]))
    ssh = [item for item in drafts if item.rule_id == "WS-SSH-WEAK-ALGORITHMS"]
    assert len(ssh) == 1
    assert set(ssh[0].observation_ids) == {first.id, second.id}
    assert set(ssh[0].evidence_artifact_ids) == {"evidence-1", "evidence-2"}
    merged = deduplicate_drafts(drafts + drafts)
    assert len([item for item in merged if item.rule_id == "WS-SSH-WEAK-ALGORITHMS"]) == 1


def test_findings_are_deterministic():
    observations = [
        sample_observation(
            data={
                "kex": ["diffie-hellman-group1-sha1"],
                "host_key": ["ssh-rsa"],
                "encryption": ["aes128-cbc"],
                "mac": ["hmac-sha1"],
            }
        )
    ]
    first = [item.model_dump() for item in evaluate_findings(_context(observations))]
    second = [item.model_dump() for item in evaluate_findings(_context(observations))]
    assert first == second
