"""Baseline parser, persist, and inventory-list timings for Milestone 3."""

from dataclasses import replace
import json
from pathlib import Path
import tempfile
from time import perf_counter

from config.settings import get_settings
from inventory.service import InventoryService
from parsers.nmap import parse_nmap_xml
from persistence.database import Database
from persistence.schema import apply_migrations
from tests.fixtures.nmap import nmaprun


def milliseconds(started: float) -> float:
    return round((perf_counter() - started) * 1_000, 3)


def synthetic_hosts(count: int) -> str:
    hosts = []
    for index in range(count):
        hosts.append(
            "<host>"
            f'<status state="up" reason="echo-reply"/>'
            f'<address addr="198.51.100.{index % 250}" addrtype="ipv4"/>'
            "<ports>"
            '<port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="ssh" product="OpenSSH" version="9.2" '
            'method="probed" conf="10"/>'
            "</port>"
            '<port protocol="tcp" portid="443">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="http" product="nginx" method="probed" conf="10"/>'
            "</port>"
            "</ports>"
            "</host>"
        )
    return nmaprun(
        "".join(hosts),
        up=count,
        down=0,
    )


def timed_parse(xml: str) -> tuple[float, int]:
    started = perf_counter()
    document = parse_nmap_xml(xml)
    return milliseconds(started), len(document.hosts)


def main() -> None:
    xml_10 = synthetic_hosts(10)
    xml_100 = synthetic_hosts(100)
    parse_10_ms, hosts_10 = timed_parse(xml_10)
    parse_100_ms, hosts_100 = timed_parse(xml_100)

    with tempfile.TemporaryDirectory(prefix="wirescope-inventory-") as temp:
        root = Path(temp)
        settings = replace(
            get_settings(),
            database_path=root / "wirescope.db",
            evidence_dir=root / "evidence",
            runtime_dir=root / "runtime",
            capture_dir=root / "runtime" / "captures",
            nmap_runtime_dir=root / "runtime" / "nmap",
        )
        apply_migrations(settings)
        database = Database(settings)
        inventory = InventoryService(database, settings)
        from jobs.service import JobService

        jobs = JobService(database)
        audit = jobs.create_audit(profile="standard", interface="eth0")
        document = parse_nmap_xml(xml_100)
        started = perf_counter()
        inventory.ingest_nmap_document(
            audit_id=audit.id,
            job_id=None,
            document=document,
        )
        persist_ms = milliseconds(started)
        started = perf_counter()
        page = inventory.list_assets(
            audit_id=audit.id,
            limit=50,
            offset=0,
        )
        list_ms = milliseconds(started)
        started = perf_counter()
        services = inventory.list_services(
            audit_id=audit.id,
            limit=100,
            offset=0,
        )
        services_ms = milliseconds(started)
        summary = inventory.summary(audit.id)
        database.dispose()

    print(
        json.dumps(
            {
                "parse_10_hosts_ms": parse_10_ms,
                "parse_10_host_count": hosts_10,
                "parse_100_hosts_ms": parse_100_ms,
                "parse_100_host_count": hosts_100,
                "persist_100_hosts_ms": persist_ms,
                "list_assets_50_ms": list_ms,
                "listed_assets": page.total,
                "list_services_100_ms": services_ms,
                "listed_services": services.total,
                "summary": summary.model_dump(mode="json"),
                "raspberry_pi_note": (
                    "These timings are a development-host baseline. A Pi 4 / "
                    "4 GB should keep inventory listing and XML parse well "
                    "under a second at this scale; Nmap runtime dominates."
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
