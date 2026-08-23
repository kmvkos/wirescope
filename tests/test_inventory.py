from inventory.models import AssetState, DeviceClassHint
from inventory.service import InventoryService
from parsers.nmap import parse_nmap_xml
from persistence.models import AssetModel, AssetObservationModel, ServiceModel
from sqlalchemy import func, select
from tests.fixtures.nmap import fixture_path


def service(database, durable_settings, evidence_store):
    return InventoryService(database, durable_settings, evidence_store)


def test_same_ip_and_service_are_idempotent(
    database,
    durable_settings,
    evidence_store,
    job_service,
):
    audit = job_service.create_audit(profile="standard", interface="eth0")
    inventory = service(database, durable_settings, evidence_store)
    document = parse_nmap_xml(fixture_path("linux_host.xml"))
    inventory.ingest_nmap_document(audit_id=audit.id, job_id=None, document=document)
    inventory.ingest_nmap_document(audit_id=audit.id, job_id=None, document=document)
    page = inventory.list_assets(audit_id=audit.id, limit=10, offset=0)
    assert page.total == 1
    detail = inventory.get_asset(audit.id, page.items[0].id)
    assert len(detail.addresses) == 1
    assert detail.addresses[0].address == "192.0.2.10"
    services = inventory.list_services(audit_id=audit.id, limit=10, offset=0)
    assert services.total == 2
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(ServiceModel)) == 2


def test_mac_correlates_passive_and_active(
    database,
    durable_settings,
    evidence_store,
    job_service,
):
    audit = job_service.create_audit(profile="standard", interface="eth0")
    inventory = service(database, durable_settings, evidence_store)
    inventory.ingest_passive_sensors(
        audit_id=audit.id,
        job_id=None,
        sensors={
            "arp": {
                "observations": [
                    {
                        "data": {
                            "sender_mac": "00:11:22:33:44:55",
                            "sender_ipv4": "192.0.2.10",
                        }
                    }
                ]
            },
            "dhcpv4": {
                "observations": [
                    {
                        "data": {
                            "client_mac": "00:11:22:33:44:55",
                            "hostname": "linux-dhcp",
                            "offered_ip": "192.0.2.10",
                        }
                    }
                ]
            },
            "mdns": {
                "observations": [
                    {
                        "data": {
                            "response_names": ["linux.local"],
                            "addresses": ["192.0.2.10"],
                        },
                        "metadata": {"source_mac": "00:11:22:33:44:55"},
                    }
                ]
            },
        },
    )
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    page = inventory.list_assets(audit_id=audit.id, limit=10, offset=0)
    assert page.total == 1
    asset = inventory.get_asset(audit.id, page.items[0].id)
    assert asset.mac == "00:11:22:33:44:55"
    assert asset.state == AssetState.RESPONSIVE
    sources = {(item.name, item.source) for item in asset.names}
    assert ("linux-dhcp", "dhcp") in sources
    assert ("linux.local", "mdns") in sources
    assert ("linux.example.test", "nmap") in sources
    assert asset.vendor is not None
    assert asset.device_class_hint in {
        DeviceClassHint.SERVER,
        DeviceClassHint.UNKNOWN,
    }


def test_multiple_addresses_and_conflicting_identity_are_preserved(
    database,
    durable_settings,
    evidence_store,
    job_service,
):
    audit = job_service.create_audit(profile="standard", interface="eth0")
    inventory = service(database, durable_settings, evidence_store)
    inventory.ingest_passive_sensors(
        audit_id=audit.id,
        job_id=None,
        sensors={
            "arp": {
                "observations": [
                    {
                        "data": {
                            "sender_mac": "00:11:22:33:44:55",
                            "sender_ipv4": "192.0.2.10",
                        }
                    },
                    {
                        "data": {
                            "sender_mac": "00:50:56:00:00:02",
                            "sender_ipv4": "192.0.2.20",
                        }
                    },
                ]
            }
        },
    )
    conflict_xml = (
        '<?xml version="1.0"?>'
        '<nmaprun scanner="nmap" args="nmap -sn" start="1700000000" '
        'version="7.95" xmloutputversion="1.05">'
        "<host>"
        '<status state="up" reason="arp-response"/>'
        '<address addr="192.0.2.20" addrtype="ipv4"/>'
        '<address addr="00:11:22:33:44:55" addrtype="mac"/>'
        "</host>"
        "<runstats>"
        '<finished time="1700000001" elapsed="1.00" summary="Nmap done"/>'
        '<hosts up="1" down="0" total="1"/>'
        "</runstats>"
        "</nmaprun>"
    )
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(conflict_xml),
    )
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("multi_service.xml")),
    )
    assets = inventory.list_assets(
        audit_id=audit.id,
        limit=20,
        offset=0,
        include_services=False,
    )
    assert assets.total >= 2
    multi = next(
        item
        for item in assets.items
        if any(address.address == "192.0.2.15" for address in item.addresses)
        or any(address.address == "2001:db8::15" for address in item.addresses)
    )
    detail = inventory.get_asset(audit.id, multi.id)
    families = {item.family for item in detail.addresses}
    assert 4 in families and 6 in families
    with database.session() as session:
        conflicts = session.scalars(
            select(AssetObservationModel).where(
                AssetObservationModel.audit_id == audit.id,
                AssetObservationModel.observation_type.in_(
                    ["identity_conflict", "mac_conflict"]
                ),
            )
        ).all()
        assert conflicts
        macs = {
            row.mac
            for row in session.scalars(
                select(AssetModel).where(AssetModel.audit_id == audit.id)
            )
        }
        assert "00:11:22:33:44:55" in macs
        assert "00:50:56:00:00:02" in macs


def test_unresponsive_cidr_hosts_are_not_materialized(
    database,
    durable_settings,
    evidence_store,
    job_service,
):
    audit = job_service.create_audit(profile="standard", interface="eth0")
    inventory = service(database, durable_settings, evidence_store)
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("no_response.xml")),
    )
    assert inventory.summary(audit.id).assets == 0
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("no_response.xml")),
        persist_unresponsive_singletons=True,
    )
    page = inventory.list_assets(audit_id=audit.id, limit=10, offset=0)
    assert page.total == 1
    assert page.items[0].state == AssetState.UNRESPONSIVE


def test_inventory_filters_and_summary(
    database,
    durable_settings,
    evidence_store,
    job_service,
):
    audit = job_service.create_audit(profile="standard", interface="eth0")
    inventory = service(database, durable_settings, evidence_store)
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("linux_host.xml")),
    )
    inventory.ingest_nmap_document(
        audit_id=audit.id,
        job_id=None,
        document=parse_nmap_xml(fixture_path("windows_host.xml")),
    )
    filtered = inventory.list_assets(
        audit_id=audit.id,
        limit=10,
        offset=0,
        hostname="linux.example.test",
    )
    assert filtered.total == 1
    ssh = inventory.list_services(
        audit_id=audit.id,
        limit=10,
        offset=0,
        port=22,
        protocol="tcp",
    )
    assert ssh.total == 1
    summary = inventory.summary(audit.id)
    assert summary.assets == 2
    assert summary.tcp_services >= 2
    assert summary.ipv4_addresses == 2
