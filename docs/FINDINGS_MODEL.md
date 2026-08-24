# WireScope findings model

Milestone 5 adds a **findings engine**. It interprets stored observations. It
does not start scanners, parse tool stdout, or run Nuclei, Nikto, or NSE.

```text
protocol_observations (M4)
inventory services (M3)
passive-result artifacts (M1)
        ↓
Declarative rules (versioned, scanner-independent)
        ↓
Correlate + deduplicate
        ↓
Persist findings + evidence links
        ↓
Optional suppress / accepted-risk audit trail
```

## Finding contract

A finding is an actionable interpretation, schema version 1:

- `rule_id` and `rule_version`;
- `severity` (`critical`, `high`, `medium`, `low`, `info`);
- `confidence` (the same enum as assessments);
- `status` (`open`, `suppressed`, `accepted_risk`);
- affected `asset_id` / `service_id` when the result is host-scoped;
- description, rationale, and recommendation;
- `observation_ids` for protocol facts;
- `evidence_artifact_ids` for raw tool or passive-result files;
- `dedupe_key` unique with `(audit_id, rule_id)`.

Observations remain facts. Findings never replace them.

## Rules

Rules live in `findings/rules/` and are registered in `findings/registry.py`.
Adding a rule does not change orchestration. Rules read only:

- `protocol_observations` kinds such as `ssh_algorithms`, `tls_session`,
  `tls_certificate`, `http_response`, `dns_flags`, `dns_identity`,
  `smb_null_session`, `snmp_unauthenticated`, and `ldap_rootdse`;
- open inventory services for insecure management protocols that M4 does not
  probe (FTP, Telnet, TFTP, r-services);
- stored `passive_result` sensor summaries for LLMNR, NBNS, and multiple DHCP
  servers.

They must not parse `ssh-audit`, OpenSSL, curl, dig, smbclient, snmpget, or
ldapsearch stdout.

Initial families:

| Rule ID | Source | Typical severity |
| ------- | ------ | ---------------- |
| `WS-SSH-WEAK-ALGORITHMS` | `ssh_algorithms` | high/medium |
| `WS-TLS-LEGACY-PROTOCOL` | `tls_session.protocol` | critical–medium |
| `WS-TLS-WEAK-CIPHER` | `tls_session.cipher` | high |
| `WS-TLS-CERT-EXPIRED` | `tls_certificate.not_after` | high |
| `WS-TLS-CERT-UNTRUSTED` | `tls_certificate.verify_code` | medium |
| `WS-HTTP-MISSING-HSTS` | HTTPS `http_response` | medium |
| `WS-HTTP-MISSING-SECURITY-HEADERS` | `http_response` headers | low |
| `WS-HTTP-SERVER-DISCLOSURE` | `Server` / `X-Powered-By` | info |
| `WS-SMB-NULL-SESSION` | `smb_null_session.accepted` | high |
| `WS-SMB-SIGNING-DISABLED` | optional `signing` field | medium |
| `WS-SMB-LEGACY-DIALECT` | optional `dialect` field | high |
| `WS-DNS-RECURSION` | `dns_flags.recursion_available` | medium |
| `WS-DNS-VERSION-DISCLOSED` | `dns_identity` | low |
| `WS-SNMP-UNAUTHENTICATED` | `snmp_unauthenticated.responded` | high |
| `WS-LDAP-ANONYMOUS-BIND` | `anonymous_bind=true` | medium |
| `WS-MGMT-INSECURE-PROTOCOL` | inventory FTP/Telnet/… | high/medium |
| `WS-INFRA-LLMNR` / `WS-INFRA-NBNS` | passive sensors | medium |
| `WS-INFRA-MULTIPLE-DHCP` | dhcpv4 summary | medium |

SMB signing and legacy-dialect rules fire only when those fields exist on a
normalized observation. M4 `smbclient -N -L` output does not currently record
them, so absence is not a finding.

## False-positive boundaries

These inputs never become security findings:

- `tool_unavailable`, `tool_timeout`, `tool_failed`, `cancelled`,
  `empty_output`, `malformed_output`, `dns_unreachable`;
- SNMP `responded=false`;
- SMB `accepted=false` without a signing/dialect field;
- LDAP `anonymous_bind=false`;
- DNS `recursion_available=false`;
- modern SSH algorithm lists and TLS 1.2/1.3 AEAD sessions with verify code 0
  and a future `not_after`;
- missing HSTS on plain HTTP;
- unparseable certificate dates.

A missing tool is not evidence that a protocol is absent.

## Deduplication and re-evaluation

Drafts merge on `(rule_id, dedupe_key)`. Re-running the job upserts the same
row, updates evidence and rationale, and **preserves** `suppressed` or
`accepted_risk`. Status changes append `finding_state_events` (`actor`,
`reason`, from/to).

## Job and API

`POST /api/audits/{id}/findings` enqueues `findings_evaluation`. The worker
takes exclusive `audit:<id>` and group `findings` (default max 1). It does
**not** take `interface:<name>` and does not invoke `ToolRunner`.

Read APIs:

- `GET /api/audits/{id}/findings` (paginated, filterable);
- `GET /api/audits/{id}/findings/{finding_id}` (includes state events);
- `POST .../suppress`, `.../accept-risk`, `.../reopen`.

Default tests stay fixture-based (`pytest -m not network`). Findings
evaluation never contacts a live network.
