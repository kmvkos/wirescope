from engine.passive_models import ConfidenceLevel
from inventory.service import InventoryService
from jobs.service import JobService
from parsers.nmap import parse_nmap_xml
from protocol_audits.models import ObservationDraft
from protocol_audits.store import ProtocolObservationStore
from tests.fixtures.nmap import fixture_path

def test_protocol_observation_upsert_is_idempotent(database, durable_settings):
    store = ProtocolObservationStore(database)
    jobs = JobService(database)
    audit = jobs.create_audit(profile="standard", interface="eth0", scope={})
    inventory = InventoryService(database, durable_settings)
    document = parse_nmap_xml(fixture_path("linux_host.xml"))
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=document,
    )
    services = inventory.list_services(audit_id=audit.id, limit=10, offset=0)
    service = next(item for item in services.items if item.port == 22)
    draft = ObservationDraft(
        kind="ssh_banner",
        data={"software": "OpenSSH_8.9p1"},
        confidence=ConfidenceLevel.HIGH,
        source="ssh-audit",
    )
    first = store.upsert_many(
        audit_id=audit.id,
        asset_id=service.asset_id,
        service_id=service.id,
        protocol="ssh",
        module="ssh",
        drafts=[draft],
        evidence_artifact_id=None,
    )
    second = store.upsert_many(
        audit_id=audit.id,
        asset_id=service.asset_id,
        service_id=service.id,
        protocol="ssh",
        module="ssh",
        drafts=[
            draft.model_copy(
                update={"data": {"software": "OpenSSH_8.9p1 Ubuntu"}}
            )
        ],
        evidence_artifact_id="artifact-1",
    )
    listing = store.list_observations(audit_id=audit.id, limit=10, offset=0)
    assert len(first) == 1
    assert len(second) == 1
    assert first[0].id == second[0].id
    assert listing.total == 1
    assert listing.items[0].id == first[0].id
    assert listing.items[0].data["software"] == "OpenSSH_8.9p1 Ubuntu"
    assert listing.items[0].last_seen >= listing.items[0].first_seen
    assert listing.items[0].evidence_artifact_id == "artifact-1"
