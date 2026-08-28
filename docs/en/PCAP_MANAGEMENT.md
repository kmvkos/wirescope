# Retained PCAP management

WireScope stores raw PCAP separately from normalized analysis results. This allows an external capture to be imported for offline analysis, and also allows a large or sensitive raw capture to be removed without erasing completed analysis history.

## Manual PCAP import

An `auditor` can add an external `.pcap` or `.pcapng` from the **Listen** screen or through the API:

```text
POST /api/v1/captures/import
Content-Type: application/octet-stream
X-WireScope-Filename: <URL-encoded filename>

<raw PCAP/PCAPNG body>
```

The file is streamed; the API does not buffer the entire PCAP in memory. The default maximum import size is **256 MiB**. The appliance policy can override it with:

```text
WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB
```

The supported policy range is `1..4096` MiB.

### Lifecycle

```text
external PCAP/PCAPNG
        ↓
bounded streaming upload
        ↓
staging under the evidence root
        ↓
size + format + SHA-256 validation
        ↓
durable packet_capture job
source_origin = imported
        ↓
worker re-validation
        ↓
ordinary packet_capture artifact
        ↓
Traffic Analysis on explicit operator action
        ↓
optional Correlated Assessment
```

An imported capture uses the same downstream lifecycle as a capture produced by WireScope. After a successful import it can therefore be:

- downloaded;
- removed with the ordinary **Delete PCAP** action;
- submitted to the existing Traffic Analysis workflow;
- re-analyzed while the raw PCAP is retained;
- used as an explicitly selected Traffic Analysis source in Correlated Assessment.

PCAPNG retains its format, extension, and media type when downloaded; it is not disguised as classic PCAP.

### Imported-PCAP trust boundary

An external PCAP is treated as a **historical untrusted observation source**. Its contents describe only what is present in the supplied file.

An imported PCAP:

- performs no network I/O;
- does not start `dumpcap`, discovery, or protocol probes;
- does not create or extend confirmed active scope;
- does not prove that the network represented in the file is currently connected to WireScope;
- does not authorize active scanning of IPs, MACs, or VLANs found only in the external file;
- is not automatically mixed into a current audit.

The durable result records at least:

```text
source_origin = imported
network_io_performed = false
active_scope_authorized = false
```

To compare an external capture with a specific audit, the operator first runs the normal Traffic Analysis for that imported file and then **explicitly selects** the completed Traffic Analysis in Correlated Assessment. Import alone never creates that relationship.

### Validation and staging

Before a durable capture job is created, the API checks that:

- the file is not empty;
- its size is within the configured limit;
- its magic/header is a supported classic PCAP or PCAPNG form;
- basic header integrity is valid;
- a SHA-256 digest is calculated over the complete file.

After the job is queued, the worker reads the staging file again and verifies size/SHA-256 before registering the final `packet_capture` artifact. This detects changes between HTTP upload and durable worker execution.

Staging is confined to the evidence root, uses a random UUID, and is written with `0600` permissions. The staging file is removed after success or failure. Old `*.tmp-*` files are also covered by WireScope's existing temporary-file cleanup.

A successful import is recorded in the operational audit log as:

```text
capture.pcap_import
```

## Manual deletion

An `auditor` may delete the raw PCAP from the GUI or API:

```text
DELETE /api/v1/captures/{capture_job_id}/pcap
```

Only the `packet_capture` artifact and its file are removed.

**Preserved:**

- durable capture/import-session history and status;
- immutable `capture_result` / `packet_capture_result` historical metadata;
- completed `traffic_analysis_result` artifacts;
- comparison/correlation results already built from normalized persisted data;
- the operational audit log.

After manual deletion:

- the entry disappears from the ordinary retained-PCAP list in the GUI;
- the original PCAP can no longer be downloaded;
- Traffic Analysis cannot be started again from that PCAP;
- already-completed Traffic Analysis remains readable and exportable;
- the historical capture job remains addressable by ID and is not deleted from durable history.

This distinction is intentional: **Delete PCAP** removes the retained raw capture and its working-list entry, not the normalized results that were already produced from it.

## Race protection

Deletion is rejected while any job in the capture audit is `queued` or `running`. The capture or downstream analysis must finish or be stopped first.

The API returns `409 pcap_delete_busy`.

## Retention and stale metadata

`audit.summary` is historical state and can outlive a raw artifact removed by retention. Capture responses therefore verify both the registered artifact and the actual file instead of trusting an old `pcap_artifact_id` alone.

If a raw artifact/file becomes unavailable without an explicit operator deletion, its capture history may still be shown as **PCAP unavailable**. This differs from manual deletion: explicitly deleted entries are hidden from the ordinary retained-PCAP list.

If the artifact/file is already unavailable, the download endpoint returns:

```text
410 pcap_unavailable
```

Repeated `DELETE` calls are safe and idempotent.

If WireScope metadata has already been removed but the physical file unlink fails, the API returns `file_cleanup_pending > 0` and the GUI surfaces an explicit storage-cleanup warning.

## Deletion safety

Before unlinking a file, the stored artifact path is validated against the configured evidence root. Metadata pointing outside that root is never used as a deletion path.

The operation is recorded in the operational audit log as:

```text
capture.pcap_delete
```
