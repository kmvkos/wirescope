from engine.passive_models import ConfidenceLevel
from findings.models import FindingDraft, FindingStatus, Severity
from findings.store import FindingStore, InvalidFindingState
from inventory.service import InventoryService
from jobs.service import JobService
from parsers.nmap import parse_nmap_xml
from tests.fixtures.nmap import fixture_path


def _seed(database, durable_settings):
    jobs = JobService(database)
    audit = jobs.create_audit(profile="standard", interface="eth0", scope={})
    inventory = InventoryService(database, durable_settings)
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    services = inventory.list_services(audit_id=audit.id, limit=10, offset=0)
    service = next(item for item in services.items if item.port == 22)
    return audit, service


def _draft(service, **overrides) -> FindingDraft:
    payload = dict(
        rule_id="WS-SSH-WEAK-ALGORITHMS",
        rule_version="1",
        family="ssh",
        title="Weak SSH algorithms are offered",
        severity=Severity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        asset_id=service.asset_id,
        service_id=service.id,
        description="Weak algorithms were observed.",
        rationale="ssh_algorithms listed weak ciphers.",
        recommendation="Disable legacy algorithms.",
        data={"weak_algorithms": {"encryption": ["aes128-cbc"]}},
        observation_ids=["obs-1"],
        evidence_artifact_ids=["evidence-1"],
        dedupe_key=f"{service.asset_id}:{service.id}",
    )
    payload.update(overrides)
    return FindingDraft(**payload)


def test_finding_upsert_is_idempotent_and_preserves_suppression(
    database,
    durable_settings,
):
    store = FindingStore(database)
    audit, service = _seed(database, durable_settings)
    first = store.upsert_evaluation(audit_id=audit.id, drafts=[_draft(service)])
    suppressed = store.change_status(
        audit_id=audit.id,
        finding_id=first[0].id,
        to_status=FindingStatus.SUPPRESSED,
        actor="auditor",
        reason="Accepted lab host",
    )
    second = store.upsert_evaluation(
        audit_id=audit.id,
        drafts=[
            _draft(
                service,
                title="Weak SSH algorithms are offered",
                data={"weak_algorithms": {"encryption": ["3des-cbc"]}},
            )
        ],
    )
    listing = store.list_findings(audit_id=audit.id, limit=10, offset=0)
    assert len(first) == 1
    assert first[0].id == second[0].id
    assert listing.total == 1
    assert listing.items[0].status == FindingStatus.SUPPRESSED
    assert listing.items[0].data["weak_algorithms"]["encryption"] == ["3des-cbc"]
    assert suppressed.state_events[0].actor == "auditor"
    assert suppressed.state_events[0].reason == "Accepted lab host"


def test_finding_state_transitions_are_audited(database, durable_settings):
    store = FindingStore(database)
    audit, service = _seed(database, durable_settings)
    created = store.upsert_evaluation(audit_id=audit.id, drafts=[_draft(service)])
    accepted = store.change_status(
        audit_id=audit.id,
        finding_id=created[0].id,
        to_status=FindingStatus.ACCEPTED_RISK,
        actor="lead",
        reason="Compensating control",
    )
    reopened = store.change_status(
        audit_id=audit.id,
        finding_id=created[0].id,
        to_status=FindingStatus.OPEN,
        actor="lead",
        reason="Control removed",
    )
    assert accepted.status == FindingStatus.ACCEPTED_RISK
    assert reopened.status == FindingStatus.OPEN
    assert [event.to_status for event in reopened.state_events] == [
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.OPEN,
    ]
    try:
        store.change_status(
            audit_id=audit.id,
            finding_id=created[0].id,
            to_status=FindingStatus.OPEN,
            actor="lead",
            reason="noop",
        )
        assert False, "expected invalid transition"
    except InvalidFindingState:
        pass
