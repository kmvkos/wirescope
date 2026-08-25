"""Runtime capability discovery for the operator UI and readiness checks."""

from __future__ import annotations

import shutil
from typing import Any

from config.settings import Settings


_TOOL_SPECS = (
    ("packet_capture", "dumpcap", "dumpcap_binary", True),
    ("packet_decode", "tshark", "tshark_binary", True),
    ("active_discovery", "nmap", "nmap_binary", False),
    ("ssh_audit", "ssh-audit", "ssh_audit_binary", False),
    ("tls_audit", "openssl", "openssl_binary", False),
    ("http_audit", "curl", "curl_binary", False),
    ("dns_audit", "dig", "dig_binary", False),
    ("smb_audit", "smbclient", "smbclient_binary", False),
    ("snmp_audit", "snmpget", "snmpget_binary", False),
    # Net-SNMP ships snmpbulkwalk together with snmpget.  Keep it optional and
    # separate so diagnostics can explain why protocol SNMP probing works while
    # topology enrichment does not.
    ("snmp_topology", "snmpbulkwalk", None, False),
    ("ldap_audit", "ldapsearch", "ldapsearch_binary", False),
)


def capability_inventory(settings: Settings) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    for capability, label, setting_name, required in _TOOL_SPECS:
        configured = str(getattr(settings, setting_name)) if setting_name else label
        resolved = shutil.which(configured)
        tools.append(
            {
                "capability": capability,
                "tool": label,
                "configured_binary": configured,
                "path": resolved,
                "available": resolved is not None,
                "required_for_core": required,
            }
        )

    required_ok = all(
        item["available"] for item in tools if item["required_for_core"]
    )
    optional_available = sum(
        1 for item in tools if not item["required_for_core"] and item["available"]
    )
    optional_total = sum(1 for item in tools if not item["required_for_core"])
    return {
        "core_ready": required_ok,
        "web": {
            "bind_host": settings.bind_host,
            "bind_port": settings.bind_port,
            "all_interfaces": settings.bind_host in {"0.0.0.0", "::"},
            "tls": settings.tls_enabled,
            "trust_proxy": settings.trust_proxy,
        },
        "tools": tools,
        "summary": {
            "required_ready": required_ok,
            "optional_available": optional_available,
            "optional_total": optional_total,
        },
        "features": {
            "html_report": True,
            "json_report": True,
            "markdown_report": True,
            "pdf_report": False,
            "audit_diff": True,
            "evidence_viewer": True,
        },
    }
