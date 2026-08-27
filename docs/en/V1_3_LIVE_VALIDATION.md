# WireScope v1.3 — live validation

[Русский](../V1_3_LIVE_VALIDATION.md)

This runbook closes the final v1.3 Global Correlation Analysis gate on an installed WireScope VM. It is not a development workflow: the goal is to validate upgrade behavior, durable execution, persisted results, history/rebuild/exports, and the operator GUI against real retained data.

## Prerequisites

You need:

- an installed WireScope appliance;
- access to the project Git checkout (commonly `/opt/wirescope` when installed there);
- healthy `wirescope-api.service` and `wirescope-worker.service` before upgrade;
- at least one Deep audit and one completed Traffic Analysis, or the ability to create them after upgrade;
- an auditor account to start Global Analysis.

Global Analysis must not create new network I/O. It operates on persisted inventory/findings, the explicitly selected Traffic Analysis, and Network Topology.

## 1. Record the pre-upgrade state

From the project checkout:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
```

Do not switch branches over unexpected local changes.

Check services:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
```

If kiosk mode is used:

```bash
systemctl is-enabled wirescope-kiosk.service
```

## 2. Switch to the v1.3 branch

```bash
cd /opt/wirescope
git fetch origin
git switch v1.3-global-correlation-analysis
git pull --ff-only origin v1.3-global-correlation-analysis
git rev-parse HEAD
```

Record the resulting commit SHA in the validation notes.

## 3. Run the normal upgrade

```bash
cd /opt/wirescope
sudo ./packaging/upgrade.sh
```

`packaging/upgrade.sh` reuses the installer, applies migrations, and explicitly restarts API/worker. An enabled kiosk is restarted as well.

After upgrade:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
```

Both services should be `active (running)`.

## 4. Check readiness

The default API port is `8000` unless `WIRESCOPE_BIND_PORT` is overridden.

```bash
curl -fsS http://127.0.0.1:8000/api/v1/ready | python3 -m json.tool
curl -fsS http://127.0.0.1:8000/api/v1/health | python3 -m json.tool
```

If the appliance uses another port, use the effective systemd/environment value.

The appliance must not report database/migrations/worker/core capture dependencies as not ready.

## 5. Verify retained inputs

In the web/kiosk UI:

1. confirm retained audits are still present;
2. confirm retained Traffic Analysis results are still present;
3. select a completed Deep audit with useful inventory/findings/topology evidence;
4. explicitly select a completed Traffic Analysis.

Global Analysis must not silently substitute the latest PCAP/traffic result.

If suitable data is unavailable, create a new Deep audit and Traffic Analysis through the normal WireScope workflow.

## 6. Start durable Global Analysis

Open **Global Analysis** from the home screen.

Validate that:

- the workspace opens without JS/UI errors;
- retained audits are available;
- completed Traffic Analysis jobs are available;
- viewer does not receive mutating controls;
- auditor can start a run.

Start the run. Queued/running state, stage/message, and progress should be visible. The job should finish as `completed` and appear in history.

## 7. Validate the canonical result

Open the completed result.

Required properties:

- `schema = global-analysis`;
- `schema_version = 1`;
- selected `traffic_analysis_job_id` matches the operator selection;
- durable `execution.job_id` matches history;
- `network_io = false`;
- `summary`, `source_health`, `coverage`, `evidence_references`, and `operator_summary` exist;
- `infrastructure_consistency.gateway/dhcp/dns` exists;
- real partial/missing topology/report evidence propagates as partial rather than being hidden;
- hostname-only identity is not used as a merge basis;
- private unknown endpoints are not labelled Internet/external without global-IP evidence.

`consistent`, `divergent`, and `insufficient` infrastructure consistency states are all valid analytical outcomes. A divergence must not crash the analysis.

## 8. Validate exports

Download JSON, TXT, and Markdown from the same result.

Verify:

- JSON remains canonical `global-analysis` v1;
- TXT/Markdown are readable and include operator summary/consistency/external communications;
- export does not enqueue another Global Analysis job;
- export does not start scanners or capture;
- evidence lineage does not expose internal filesystem paths.

## 9. Validate immutable rebuild

Save the first JSON and its job ID, then select **Rebuild**.

Expected behavior:

- a new Global Analysis job is created;
- the same Traffic Analysis is used;
- the new job has a new ID;
- the new result has a new artifact/result reference;
- `execution.rebuild_of_job_id` points to the first Global Analysis job;
- the first result remains readable and unchanged in history;
- the rebuilt result passes the canonical checks above.

Attempting rebuild with another Traffic Analysis must be rejected rather than creating ambiguous lineage.

## 10. Validate history and operational log

History should contain the initial completed run and the rebuild in the correct order with retained source/rebuild IDs.

The operational audit log should record Global Analysis starts using:

```text
global_analysis.generate
```

Request bodies, credentials, and provider stdout must not be written to the operational log.

## 11. Appliance regression smoke

After Global Analysis, re-check:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
curl -fsS http://127.0.0.1:8000/api/v1/ready | python3 -m json.tool
```

Also open normal WireScope screens and verify audits/inventory/findings, Traffic Analysis, Network Topology, and reports remain usable.

## 12. v1.3 closure criteria

Create a v1.3 checkpoint/tag only when all of the following pass:

- branch CI green;
- normal upgrade successful;
- API/worker healthy and readiness green;
- retained state preserved;
- durable Global Analysis succeeds on real data;
- canonical JSON is `global-analysis` v1;
- partial/evidence quality remains honest;
- operator GUI is usable;
- history works;
- immutable rebuild works;
- JSON/TXT/Markdown exports work;
- operational action is recorded;
- normal WireScope workflows still work.

If any item fails, do not tag v1.3. Record the job ID/result/error and fix the cause on the feature branch.

## Suggested validation record

```text
commit: <sha>
upgrade: PASS/FAIL
ready: PASS/FAIL
deep audit: <audit-id>
traffic analysis: <job-id>
global analysis: <job-id> PASS/FAIL
partial: true/false
rebuild: <job-id> PASS/FAIL
exports: JSON/TXT/MD PASS/FAIL
history: PASS/FAIL
audit log: PASS/FAIL
regression smoke: PASS/FAIL
notes: ...
```
