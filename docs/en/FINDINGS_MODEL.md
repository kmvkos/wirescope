# Findings in WireScope

[Русский](../FINDINGS_MODEL.md) · **English**

A finding is not raw scanner output and not a line copied from an external tool. It is an interpretation: a rule evaluates normalized data and creates a result with severity, confidence, rationale, recommendation, and evidence links.

## Place in the pipeline

```text
passive_result
inventory services
protocol_observations
        ↓
findings/rules/
        ↓
correlation + deduplication
        ↓
findings
        ↓
report / GUI
```

The findings engine does not touch the network. It does not invoke Nmap, Nuclei, Nikto, NSE, `ssh-audit`, OpenSSL, or any other provider tool.

## Observation and finding are different objects

Example:

```text
Observation:
TLS session negotiated TLSv1.0
```

That is a fact.

```text
Finding:
Legacy TLS protocol is enabled
severity: high
```

That is a rule-based interpretation.

Keeping the two layers separate prevents parsers from deciding policy and allows findings to be re-evaluated without producing new network traffic.

## Finding contract

Schema version 1 stores:

- `rule_id`;
- `rule_version`;
- `severity`;
- `confidence`;
- `status`;
- optional `asset_id` / `service_id`;
- title and description;
- rationale;
- recommendation;
- `observation_ids`;
- `evidence_artifact_ids`;
- `dedupe_key`.

Severity values:

```text
critical
high
medium
low
info
```

Confidence uses the common WireScope scale:

```text
confirmed
high
medium
low
hint
unknown
```

Finding states:

```text
open
suppressed
accepted_risk
```

## Data sources

Rules currently consume three main sources.

### `protocol_observations`

Examples include:

- `ssh_algorithms`;
- `tls_session`;
- `tls_certificate`;
- `http_response`;
- `dns_flags`;
- `dns_identity`;
- `smb_null_session`;
- `snmp_unauthenticated`;
- `ldap_rootdse`.

### Inventory

Some rules only need the fact that a service is exposed. An insecure management protocol can therefore be detected from inventory even if no dedicated protocol module exists for it.

### Passive result

Passive rules may consume stored sensor summaries and assessment data, for example LLMNR, NBNS, or multiple DHCP servers.

## Rule registry

Rules live under:

```text
findings/rules/
```

and are registered through the findings registry.

Adding a rule does not require changes to worker or scanner orchestration.

Rules must operate on normalized data. Parsing raw `ssh-audit`, OpenSSL, curl, dig, smbclient, or other provider stdout inside a finding rule is not part of the model.

## Current rule families

| Rule | Source | Typical severity |
| --- | --- | --- |
| `WS-SSH-WEAK-ALGORITHMS` | SSH algorithms | high / medium |
| `WS-TLS-LEGACY-PROTOCOL` | TLS protocol | critical–medium |
| `WS-TLS-WEAK-CIPHER` | TLS cipher | high |
| `WS-TLS-CERT-EXPIRED` | certificate date | high |
| `WS-TLS-CERT-UNTRUSTED` | verify code | medium |
| `WS-HTTP-MISSING-HSTS` | HTTPS response | medium |
| `WS-HTTP-MISSING-SECURITY-HEADERS` | HTTP headers | low |
| `WS-HTTP-SERVER-DISCLOSURE` | response headers | info |
| `WS-SMB-NULL-SESSION` | SMB observation | high |
| `WS-SMB-SIGNING-DISABLED` | SMB signing field | medium |
| `WS-SMB-LEGACY-DIALECT` | SMB dialect field | high |
| `WS-DNS-RECURSION` | DNS flags | medium |
| `WS-DNS-VERSION-DISCLOSED` | CHAOS identity | low |
| `WS-SNMP-UNAUTHENTICATED` | SNMP response | high |
| `WS-LDAP-ANONYMOUS-BIND` | LDAP base DSE | medium |
| `WS-MGMT-INSECURE-PROTOCOL` | inventory service | high / medium |
| `WS-INFRA-LLMNR` / `WS-INFRA-NBNS` | passive sensors | medium |
| `WS-INFRA-MULTIPLE-DHCP` | DHCP summary | medium |

SMB signing and legacy-dialect rules only fire when those normalized fields actually exist. The current `smbclient -N -L` path does not always produce them, so a missing field is not treated as evidence.

## False-positive boundaries

Provider failures are not converted into security findings.

The following do not create findings by themselves:

- `tool_unavailable`;
- timeout;
- `tool_failed`;
- cancellation;
- empty or malformed output;
- `dns_unreachable`;
- `snmp_unauthenticated.responded=false`;
- SMB refusal without signing/dialect facts;
- `anonymous_bind=false`;
- `recursion_available=false`;
- an unparseable certificate date;
- missing HSTS on plain HTTP.

The key distinction is:

```text
tool missing ≠ protocol absent ≠ secure configuration
```

Those are three different states.

## Deduplication

Draft findings are merged using stable rule/deduplication identity.

Database uniqueness is based around `(audit_id, rule_id, dedupe_key)`.

Re-running `findings_evaluation` updates the existing finding and its evidence links instead of appending a duplicate on every run.

## Suppression and accepted risk

An operator may move a finding from `open` to:

- `suppressed`;
- `accepted_risk`;
- or back to `open`.

Each state change appends an event with actor, reason, and from/to state.

A later re-evaluation must not silently erase `suppressed` or `accepted_risk` state just because the rule matched again.

## Job model

```text
POST /api/audits/{id}/findings
```

enqueues:

```text
findings_evaluation
```

The job uses an audit-level lock and the findings resource group. It does not need an interface lock because it does not access the network.

## API

Main endpoints:

```text
POST /api/audits/{id}/findings
GET  /api/audits/{id}/findings
GET  /api/audits/{id}/findings/{finding_id}
POST /api/audits/{id}/findings/{finding_id}/suppress
POST /api/audits/{id}/findings/{finding_id}/accept-risk
POST /api/audits/{id}/findings/{finding_id}/reopen
```

The list endpoint is paginated and filterable.

## Testing

Findings evaluation is fixture-based and does not require a live network.

A normal:

```bash
pytest
```

run therefore tests findings logic without launching network probes. Severity, correlation, deduplication, and false-positive boundaries can be tested deterministically from fixed observations.
