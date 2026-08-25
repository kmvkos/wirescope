# WireScope — Post-1.0 Roadmap

This roadmap starts after the v1 feature freeze. New capabilities must preserve v1 safety contracts: observed traffic is not authorization for active scanning, active scope is operator-confirmed, external tools are executed without a shell, and evidence remains reproducible.

## v1.0 — Base network auditor

Status: **feature complete / frozen**.

The release includes passive discovery, standalone PCAP capture, confirmed Discovery/Standard/Deep active scope, inventory, safe protocol audits, findings, HTML/JSON/Markdown reports, audit diff, evidence viewer, diagnostics, retention/retry, web/kiosk UI, report deletion and full deletion of inactive audits.

After freeze, only defect fixes and release engineering belong on the v1.0 line.

## v1.1 — PCAP Traffic Analysis

Goal: turn Listen/Record from simple PCAP retention into a standalone traffic diagnostic workflow.

### M10.1 — deterministic analysis of a retained PCAP

A completed or operator-stopped capture can be analyzed without new network activity. Analysis is a durable job whose source of truth is the retained PCAP evidence.

Initial output:
- duration, frames and bytes;
- unique MAC/IPv4/IPv6 endpoints;
- top talkers by packets and bytes;
- dominant protocol distribution;
- most active endpoint pairs;
- TCP health signals such as retransmission, duplicate ACK, out-of-order, reset and zero-window;
- DNS queries, NXDOMAIN/SERVFAIL and frequent names;
- ARP IP↔MAC observations and conflict/change hints;
- DHCP server hints;
- broadcast/multicast share and contributors;
- clear-text/legacy protocol observations;
- deterministic wording that separates observed fact, possible meaning and recommended verification.

Outputs:
- canonical `traffic-analysis` JSON;
- readable Russian TXT;
- Markdown export;
- web and kiosk presentation.

### M10.2 — communications graph data

The analyzer also persists normalized endpoint relationships with directional packet/byte counts, observed protocols/ports, first/last seen, provenance=`pcap`, confidence=`observed`. This becomes an input to topology rather than a separate competing model.

### M10.3 — expanded diagnostics

After the base analyzer is stable: handshake failures/SYN retransmissions, defensible RTT/latency hints, DNS latency/timeouts, DHCP sequences, ARP storms/unanswered ARP, broadcast/multicast contributors, TLS metadata without payload decryption, SMB/DNS/HTTP/QUIC summaries and capture-to-capture comparison.

## v1.2 — Network Topology

Goal: render a useful map of the observed network while exposing the provenance and confidence of every relationship.

### M11.1 — logical topology

Inputs include inventory, ARP, default routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery and PCAP communication edges.

Relationship confidence:
- `confirmed` — direct structural evidence such as LLDP/CDP;
- `observed` — actual traffic observed in PCAP;
- `inferred` — conservative inference from subnet/VLAN/route/ARP context.

The UI must show provenance rather than presenting inferred links as physical facts.

### M11.2 — interactive visualization

Planned web/kiosk features: zoom/pan, VLAN/subnet and relationship filters, asset drill-down, traffic-weighted communication edges, gateway/DHCP/DNS/network-device emphasis, and controlled topology export.

### M11.3 — deeper physical topology

Post-v1.2 candidates: safe traceroute/upstream view, explicitly configured read-only SNMP, bridge/FDB/ARP table collection, switch-port mapping and historical topology diff.

WireScope must not invent an invisible L2 switch. Physical relationships require evidence; otherwise they remain logical/inferred.

## Current next step

**M10.1 — PCAP Traffic Analysis.**

M10.1 is complete when a completed or stopped capture can be analyzed from the GUI, the result is reproducibly derived only from retained PCAP evidence, JSON and readable Russian text are available, basic network diagnostics are included, and communication edges are produced for M11.
