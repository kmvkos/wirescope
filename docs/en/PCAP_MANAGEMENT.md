# Retained PCAP management

WireScope stores raw PCAP separately from normalized analysis results. A large or sensitive capture can therefore be removed without erasing the history of completed work.

## Manual deletion

An `auditor` may delete the raw PCAP from the GUI or API:

```text
DELETE /api/v1/captures/{capture_job_id}/pcap
```

Only the `packet_capture` artifact and its file are removed.

**Preserved:**

- durable capture-session history and status;
- immutable `capture_result` historical metadata;
- completed `traffic_analysis_result` artifacts;
- comparison/correlation results already built from normalized persisted data;
- the operational audit log.

After manual deletion:

- the entry disappears from the ordinary retained-PCAP list in the GUI;
- the original PCAP can no longer be downloaded;
- Traffic Analysis cannot be started again from that capture;
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

## Safety

Before unlinking a file, the stored artifact path is validated against the configured evidence root. Metadata pointing outside that root is never used as a deletion path.

The operation is recorded in the operational audit log as:

```text
capture.pcap_delete
```
