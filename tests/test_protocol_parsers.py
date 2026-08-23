from parsers.protocol.dns import parse_dig
from parsers.protocol.http import parse_curl_http
from parsers.protocol.ldap import parse_ldapsearch
from parsers.protocol.smb import parse_smbclient
from parsers.protocol.snmp import parse_snmpget
from parsers.protocol.ssh import parse_ssh_audit
from parsers.protocol.tls import parse_openssl_sclient
from providers.tools import ToolError, ToolErrorCode
from tests.fixtures.protocol import fixture_text
from tests.helpers import tool_result


def test_ssh_json_and_text_fixtures_parse_algorithms():
    json_drafts = parse_ssh_audit(
        tool_result(tool="ssh-audit", stdout=fixture_text("ssh-audit.json"))
    )
    text_drafts = parse_ssh_audit(
        tool_result(tool="ssh-audit", stdout=fixture_text("ssh-audit.txt"))
    )
    for drafts in (json_drafts, text_drafts):
        kinds = {item.kind for item in drafts}
        assert "ssh_banner" in kinds
        assert "ssh_algorithms" in kinds
        algorithms = next(item for item in drafts if item.kind == "ssh_algorithms")
        assert "curve25519-sha256" in algorithms.data["kex"]
        assert "vulnerable" not in algorithms.kind


def test_ssh_nonzero_exit_still_parses_stdout():
    drafts = parse_ssh_audit(
        tool_result(
            tool="ssh-audit",
            stdout=fixture_text("ssh-audit.json"),
            exit_code=1,
            success=False,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="warnings"),
        )
    )
    assert any(item.kind == "ssh_algorithms" for item in drafts)


def test_tls_fixture_records_protocol_cipher_and_certificate():
    drafts = parse_openssl_sclient(
        tool_result(
            tool="openssl",
            stdout=fixture_text("openssl-s_client.txt"),
            exit_code=1,
            success=False,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="eof"),
        )
    )
    session = next(item for item in drafts if item.kind == "tls_session")
    cert = next(item for item in drafts if item.kind == "tls_certificate")
    assert session.data["protocol"] == "TLSv1.3"
    assert session.data["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert "linux.example.test" in cert.data["subject"]
    assert "weak" not in session.kind


def test_http_fixture_records_status_server_and_title():
    drafts = parse_curl_http(
        tool_result(tool="curl", stdout=fixture_text("curl-http.txt"))
    )
    assert drafts[0].kind == "http_response"
    assert drafts[0].data["status_code"] == 200
    assert drafts[0].data["headers"]["server"] == "nginx/1.22.1"
    assert drafts[0].data["title"] == "Welcome"


def test_dns_fixture_records_version_and_recursion_flag():
    drafts = parse_dig(
        tool_result(tool="dig", stdout=fixture_text("dig-version.txt"))
    )
    identity = next(item for item in drafts if item.kind == "dns_identity")
    flags = next(item for item in drafts if item.kind == "dns_flags")
    assert identity.data["version"] == "BIND 9.18.12"
    assert flags.data["recursion_available"] is True


def test_smb_null_session_acceptance_and_refusal():
    accepted = parse_smbclient(
        tool_result(tool="smbclient", stdout=fixture_text("smbclient-list.txt"))
    )
    denied = parse_smbclient(
        tool_result(
            tool="smbclient",
            stdout=fixture_text("smbclient-denied.txt"),
            exit_code=1,
            success=False,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="denied"),
        )
    )
    assert accepted[0].data["accepted"] is True
    assert accepted[0].data["share_count"] >= 1
    assert denied[0].data["accepted"] is False
    assert "ACCESS_DENIED" in denied[0].data["status"]


def test_snmp_timeout_is_not_protocol_absence():
    drafts = parse_snmpget(
        tool_result(
            tool="snmpget",
            stderr=fixture_text("snmpget-timeout.txt"),
            exit_code=1,
            success=False,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="timeout"),
        )
    )
    assert drafts[0].kind == "snmp_unauthenticated"
    assert drafts[0].data["responded"] is False
    usm = parse_snmpget(
        tool_result(
            tool="snmpget",
            stderr=fixture_text("snmpget-usm.txt"),
            exit_code=1,
            success=False,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="usm"),
        )
    )
    assert usm[0].data["responded"] is True


def test_ldap_rootdse_and_anonymous_refusal():
    drafts = parse_ldapsearch(
        tool_result(tool="ldapsearch", stdout=fixture_text("ldapsearch-rootdse.txt"))
    )
    assert drafts[0].kind == "ldap_rootdse"
    assert drafts[0].data["attributes"]["namingcontexts"] == ["DC=example,DC=test"]


def test_missing_tool_is_not_protocol_absence():
    drafts = parse_ssh_audit(
        tool_result(
            tool="ssh-audit",
            success=False,
            exit_code=None,
            error=ToolError(
                code=ToolErrorCode.MISSING_BINARY,
                message="Tool not found: ssh-audit",
            ),
        )
    )
    assert drafts[0].kind == "tool_unavailable"
    assert "absent" not in drafts[0].kind


def test_malformed_and_empty_output_are_explicit():
    malformed = parse_ssh_audit(tool_result(tool="ssh-audit", stdout="{not json"))
    empty = parse_curl_http(tool_result(tool="curl", stdout=""))
    assert malformed[0].kind == "malformed_output"
    assert empty[0].kind == "empty_output"


def test_timeout_and_failure_categories():
    timeout = parse_openssl_sclient(
        tool_result(
            tool="openssl",
            success=False,
            exit_code=None,
            error=ToolError(code=ToolErrorCode.TIMEOUT, message="timeout"),
        ).model_copy(update={"timed_out": True})
    )
    failed = parse_dig(
        tool_result(
            tool="dig",
            success=False,
            exit_code=2,
            error=ToolError(code=ToolErrorCode.NON_ZERO_EXIT, message="fail"),
        )
    )
    assert timeout[0].kind == "tool_timeout"
    assert failed[0].kind == "tool_failed"
