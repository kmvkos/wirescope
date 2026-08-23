"""Persistent authorized-scope, asset, and service inventory."""

from datetime import datetime
import hashlib
import json
from typing import Any
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from config.settings import Settings, get_settings
from engine.passive_models import ConfidenceLevel
from engine.scope import ActiveProfile, ValidatedScope
from inventory.classify import classify_device
from inventory.models import (
    AssetAddressRecord,
    AssetNameRecord,
    AssetRecord,
    AssetState,
    ConfirmedScopeRecord,
    DeviceClassHint,
    InventoryPage,
    InventorySummary,
    ServiceRecord,
)
from inventory.normalize import canonical_ip, canonical_mac, escape_like
from inventory.vendor import OuiResolver
from parsers.nmap import NmapHost, NmapScanDocument
from persistence.database import Database
from jobs.models import ArtifactRecord, RetentionClass
from persistence.models import (
    ArtifactModel,
    AssetAddressModel,
    AssetModel,
    AssetNameModel,
    AssetObservationModel,
    ConfirmedScopeModel,
    ServiceModel,
    utc_now,
)
from storage.evidence import EvidenceStore


SOURCE_CONFIDENCE = {
    "arp": ConfidenceLevel.HIGH,
    "dhcp": ConfidenceLevel.HIGH,
    "mdns": ConfidenceLevel.MEDIUM,
    "llmnr": ConfidenceLevel.MEDIUM,
    "nbns": ConfidenceLevel.MEDIUM,
    "nmap": ConfidenceLevel.HIGH,
    "ptr": ConfidenceLevel.MEDIUM,
}


class InventoryService:
    def __init__(
        self,
        database: Database,
        settings: Settings | None = None,
        evidence_store: EvidenceStore | None = None,
        vendor_resolver: OuiResolver | None = None,
    ) -> None:
        self.database = database
        self.settings = settings or get_settings()
        self.evidence_store = evidence_store
        self.vendors = vendor_resolver or OuiResolver(self.settings)

    def confirm_scope(
        self,
        *,
        audit_id: str,
        scope: ValidatedScope,
        interface: str,
        route_context: dict[str, Any],
        actor: str | None = None,
        timing_policy: str,
    ) -> ConfirmedScopeRecord:
        snapshot_hash = scope_snapshot_hash(
            profile=scope.profile,
            interface=interface,
            targets=scope.canonical_targets,
        )
        with self.database.session() as session, session.begin():
            existing = session.scalar(
                select(ConfirmedScopeModel).where(
                    ConfirmedScopeModel.audit_id == audit_id,
                    ConfirmedScopeModel.snapshot_hash == snapshot_hash,
                )
            )
            if existing is not None:
                return self._scope_record(existing)
            model = ConfirmedScopeModel(
                id=str(uuid.uuid4()),
                audit_id=audit_id,
                profile=scope.profile.value,
                interface=interface,
                targets=list(scope.canonical_targets),
                address_families=list(scope.address_families),
                address_count=scope.address_count,
                route_context=route_context,
                timing_policy=timing_policy,
                actor=actor,
                snapshot_hash=snapshot_hash,
            )
            session.add(model)
            session.flush()
            return self._scope_record(model)

    def get_scope(self, scope_id: str) -> ConfirmedScopeRecord | None:
        with self.database.session() as session:
            model = session.get(ConfirmedScopeModel, scope_id)
            return None if model is None else self._scope_record(model)

    def latest_scope(self, audit_id: str) -> ConfirmedScopeRecord | None:
        with self.database.session() as session:
            model = session.scalar(
                select(ConfirmedScopeModel)
                .where(ConfirmedScopeModel.audit_id == audit_id)
                .order_by(ConfirmedScopeModel.created_at.desc())
                .limit(1)
            )
            return None if model is None else self._scope_record(model)

    def activate_scope(self, scope_id: str) -> ConfirmedScopeRecord:
        with self.database.session() as session, session.begin():
            model = session.get(ConfirmedScopeModel, scope_id)
            if model is None:
                raise LookupError(f"Confirmed scope not found: {scope_id}")
            if model.activated_at is None:
                model.activated_at = utc_now()
            return self._scope_record(model)

    def ingest_nmap_document(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        document: NmapScanDocument,
        source: str = "nmap",
        evidence_reference: str | None = None,
        persist_unresponsive_singletons: bool = False,
    ) -> int:
        persisted = 0
        with self.database.session() as session, session.begin():
            for host in document.hosts:
                if self._upsert_nmap_host(
                    session,
                    audit_id=audit_id,
                    job_id=job_id,
                    host=host,
                    source=source,
                    evidence_reference=evidence_reference,
                    persist_unresponsive_singletons=(
                        persist_unresponsive_singletons
                    ),
                ):
                    persisted += 1
        return persisted

    def ingest_passive_from_audit(
        self,
        audit_id: str,
        job_id: str | None = None,
    ) -> int:
        if self.evidence_store is None:
            return 0
        with self.database.session() as session:
            artifact_id = session.scalar(
                select(ArtifactModel.id)
                .where(
                    ArtifactModel.audit_id == audit_id,
                    ArtifactModel.artifact_type == "passive_result",
                )
                .order_by(ArtifactModel.created_at.desc())
                .limit(1)
            )
        if artifact_id is None:
            return 0
        with self.database.session() as session:
            model = session.get(ArtifactModel, artifact_id)
            if model is None:
                return 0
            record = ArtifactRecord(
                id=model.id,
                audit_id=model.audit_id,
                job_id=model.job_id,
                artifact_type=model.artifact_type,
                relative_path=model.relative_path,
                content_type=model.content_type,
                size=model.size,
                sha256=model.sha256,
                created_at=model.created_at,
                retention_class=RetentionClass(model.retention_class),
                schema_name=model.schema_name,
                schema_version=model.schema_version,
            )
        document = self.evidence_store.read_json(record)
        sensors = document.get("result", {}).get("sensors", {})
        return self.ingest_passive_sensors(
            audit_id=audit_id,
            job_id=job_id,
            sensors=sensors,
            evidence_reference=artifact_id,
        )

    def ingest_passive_sensors(
        self,
        *,
        audit_id: str,
        job_id: str | None,
        sensors: dict[str, Any],
        evidence_reference: str | None = None,
    ) -> int:
        created_or_updated = 0
        with self.database.session() as session, session.begin():
            created_or_updated += self._ingest_arp(
                session, audit_id, job_id, sensors, evidence_reference
            )
            created_or_updated += self._ingest_dhcp(
                session, audit_id, job_id, sensors, evidence_reference
            )
            for sensor_name in ("mdns", "llmnr", "nbns"):
                created_or_updated += self._ingest_naming(
                    session,
                    audit_id,
                    job_id,
                    sensor_name,
                    sensors,
                    evidence_reference,
                )
            self._refresh_classifications(session, audit_id)
        return created_or_updated

    def refresh_classifications(self, audit_id: str) -> None:
        with self.database.session() as session, session.begin():
            self._refresh_classifications(session, audit_id)

    def summary(self, audit_id: str) -> InventorySummary:
        with self.database.session() as session:
            assets = session.scalar(
                select(func.count()).select_from(AssetModel).where(
                    AssetModel.audit_id == audit_id
                )
            ) or 0
            services = session.scalar(
                select(func.count()).select_from(ServiceModel).where(
                    ServiceModel.audit_id == audit_id
                )
            ) or 0
            tcp_services = session.scalar(
                select(func.count()).select_from(ServiceModel).where(
                    ServiceModel.audit_id == audit_id,
                    ServiceModel.protocol == "tcp",
                )
            ) or 0
            udp_services = session.scalar(
                select(func.count()).select_from(ServiceModel).where(
                    ServiceModel.audit_id == audit_id,
                    ServiceModel.protocol == "udp",
                )
            ) or 0
            ipv4_addresses = session.scalar(
                select(func.count()).select_from(AssetAddressModel).where(
                    AssetAddressModel.audit_id == audit_id,
                    AssetAddressModel.family == 4,
                )
            ) or 0
            ipv6_addresses = session.scalar(
                select(func.count()).select_from(AssetAddressModel).where(
                    AssetAddressModel.audit_id == audit_id,
                    AssetAddressModel.family == 6,
                )
            ) or 0
            class_rows = session.execute(
                select(
                    AssetModel.device_class_hint,
                    func.count(),
                )
                .where(AssetModel.audit_id == audit_id)
                .group_by(AssetModel.device_class_hint)
            ).all()
        return InventorySummary(
            assets=assets,
            services=services,
            tcp_services=tcp_services,
            udp_services=udp_services,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            device_classes={name: count for name, count in class_rows},
        )

    def list_assets(
        self,
        *,
        audit_id: str,
        limit: int,
        offset: int,
        address: str | None = None,
        hostname: str | None = None,
        mac: str | None = None,
        vendor: str | None = None,
        state: AssetState | None = None,
        device_class: DeviceClassHint | None = None,
        include_services: bool = False,
    ) -> InventoryPage[AssetRecord]:
        with self.database.session() as session:
            filters = [AssetModel.audit_id == audit_id]
            if state is not None:
                filters.append(AssetModel.state == state.value)
            if device_class is not None:
                filters.append(
                    AssetModel.device_class_hint == device_class.value
                )
            if vendor:
                filters.append(
                    AssetModel.vendor.ilike(
                        f"%{escape_like(vendor)}%",
                        escape="\\",
                    )
                )
            if mac:
                normalized = canonical_mac(mac) or mac
                filters.append(
                    AssetModel.mac.ilike(
                        f"%{escape_like(normalized)}%",
                        escape="\\",
                    )
                )
            if address:
                filters.append(
                    AssetModel.addresses.any(
                        AssetAddressModel.address.ilike(
                            f"%{escape_like(address)}%",
                            escape="\\",
                        )
                    )
                )
            if hostname:
                filters.append(
                    AssetModel.names.any(
                        AssetNameModel.name.ilike(
                            f"%{escape_like(hostname)}%",
                            escape="\\",
                        )
                    )
                )
            options = [
                selectinload(AssetModel.addresses),
                selectinload(AssetModel.names),
            ]
            if include_services:
                options.append(selectinload(AssetModel.services))
            query = (
                select(AssetModel)
                .where(*filters)
                .options(*options)
                .order_by(AssetModel.last_seen.desc(), AssetModel.id)
            )
            total = session.scalar(
                select(func.count()).select_from(AssetModel).where(*filters)
            ) or 0
            rows = session.scalars(query.limit(limit).offset(offset)).all()
            items = [
                self._asset_record(row, include_services=include_services)
                for row in rows
            ]
        return InventoryPage[AssetRecord](
            items=items,
            limit=limit,
            offset=offset,
            total=total,
        )

    def get_asset(self, audit_id: str, asset_id: str) -> AssetRecord | None:
        with self.database.session() as session:
            model = session.scalar(
                select(AssetModel)
                .where(
                    AssetModel.audit_id == audit_id,
                    AssetModel.id == asset_id,
                )
                .options(
                    selectinload(AssetModel.addresses),
                    selectinload(AssetModel.names),
                    selectinload(AssetModel.services),
                )
            )
            if model is None:
                return None
            return self._asset_record(model, include_services=True)

    def list_services(
        self,
        *,
        audit_id: str,
        limit: int,
        offset: int,
        asset_id: str | None = None,
        protocol: str | None = None,
        port: int | None = None,
        state: str | None = None,
        service_name: str | None = None,
        product: str | None = None,
    ) -> InventoryPage[ServiceRecord]:
        with self.database.session() as session:
            filters = [ServiceModel.audit_id == audit_id]
            if asset_id:
                filters.append(ServiceModel.asset_id == asset_id)
            if protocol:
                filters.append(ServiceModel.protocol == protocol.lower())
            if port is not None:
                filters.append(ServiceModel.port == port)
            if state:
                filters.append(ServiceModel.state == state)
            if service_name:
                filters.append(
                    ServiceModel.service_name.ilike(
                        f"%{escape_like(service_name)}%",
                        escape="\\",
                    )
                )
            if product:
                filters.append(
                    ServiceModel.product.ilike(
                        f"%{escape_like(product)}%",
                        escape="\\",
                    )
                )
            total = session.scalar(
                select(func.count()).select_from(ServiceModel).where(*filters)
            ) or 0
            rows = session.scalars(
                select(ServiceModel)
                .where(*filters)
                .order_by(
                    ServiceModel.protocol,
                    ServiceModel.port,
                    ServiceModel.id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
            items = [self._service_record(row) for row in rows]
        return InventoryPage[ServiceRecord](
            items=items,
            limit=limit,
            offset=offset,
            total=total,
        )

    def _upsert_nmap_host(
        self,
        session: Session,
        *,
        audit_id: str,
        job_id: str | None,
        host: NmapHost,
        source: str,
        evidence_reference: str | None,
        persist_unresponsive_singletons: bool,
    ) -> bool:
        mac = canonical_mac(host.mac)
        addresses = []
        for item in host.addresses:
            if item.family not in {"ipv4", "ipv6"}:
                continue
            try:
                addresses.append(canonical_ip(item.address))
            except ValueError:
                continue
        interesting = (
            host.status == "up"
            or mac is not None
            or bool(host.hostnames)
            or bool(host.ports)
        )
        if not interesting:
            if persist_unresponsive_singletons and host.status == "down":
                interesting = True
            else:
                return False

        state = _host_state(host.status)
        asset, conflict = self._correlate(
            session,
            audit_id=audit_id,
            mac=mac,
            addresses=addresses,
        )
        now = utc_now()
        if asset is None:
            vendor = self.vendors.lookup(mac)
            asset = AssetModel(
                id=str(uuid.uuid4()),
                audit_id=audit_id,
                state=state.value,
                mac=mac,
                vendor=vendor.vendor or host.mac_vendor,
                vendor_source=vendor.source,
                vendor_database_version=vendor.database_version,
                device_class_hint=DeviceClassHint.UNKNOWN.value,
                device_class_confidence=ConfidenceLevel.UNKNOWN.value,
                first_seen=now,
                last_seen=now,
                metadata_json={},
            )
            session.add(asset)
            session.flush()
        else:
            asset.last_seen = now
            self._merge_state(asset, state)
            if mac and asset.mac is None:
                other = self._asset_by_mac(session, audit_id, mac)
                if other is None or other.id == asset.id:
                    asset.mac = mac
                    vendor = self.vendors.lookup(mac)
                    if vendor.vendor and not asset.vendor:
                        asset.vendor = vendor.vendor
                        asset.vendor_source = vendor.source
                        asset.vendor_database_version = (
                            vendor.database_version
                        )
            elif mac and asset.mac and asset.mac != mac:
                self._observe(
                    session,
                    audit_id=audit_id,
                    asset_id=asset.id,
                    job_id=job_id,
                    observation_type="mac_conflict",
                    source=source,
                    evidence_reference=evidence_reference,
                    data={"existing": asset.mac, "observed": mac},
                )

        if conflict:
            self._observe(
                session,
                audit_id=audit_id,
                asset_id=asset.id,
                job_id=job_id,
                observation_type="identity_conflict",
                source=source,
                evidence_reference=evidence_reference,
                data=conflict,
            )

        blocked = set(conflict.get("blocked_addresses", []) if conflict else [])
        primary_set = False
        for address, family in addresses:
            if address in blocked:
                continue
            self._upsert_address(
                session,
                audit_id=audit_id,
                asset=asset,
                address=address,
                family=family,
                source=source,
                now=now,
                is_primary=not primary_set,
            )
            primary_set = True

        for hostname in host.hostnames:
            self._upsert_name(
                session,
                audit_id=audit_id,
                asset=asset,
                name=hostname.name,
                name_type=hostname.name_type or "PTR",
                source="nmap",
                now=now,
            )

        self._apply_os_hint(session, asset, host, job_id, evidence_reference)
        for port in host.ports:
            self._upsert_service(
                session,
                audit_id=audit_id,
                asset=asset,
                host_port=port,
                source=source,
                now=now,
            )
        self._observe(
            session,
            audit_id=audit_id,
            asset_id=asset.id,
            job_id=job_id,
            observation_type="nmap_host",
            source=source,
            evidence_reference=evidence_reference,
            data={
                "status": host.status,
                "reason": host.status_reason,
                "addresses": [address for address, _family in addresses],
                "mac": mac,
            },
        )
        session.flush()
        self._classify_asset(session, asset)
        return True

    def _correlate(
        self,
        session: Session,
        *,
        audit_id: str,
        mac: str | None,
        addresses: list[tuple[str, int]],
    ) -> tuple[AssetModel | None, dict[str, Any]]:
        by_mac = self._asset_by_mac(session, audit_id, mac) if mac else None
        address_assets: dict[str, AssetModel] = {}
        for address, _family in addresses:
            found = self._asset_by_address(session, audit_id, address)
            if found is not None:
                address_assets[address] = found

        unique_ip_assets = {asset.id: asset for asset in address_assets.values()}
        conflict: dict[str, Any] = {}
        if by_mac is not None:
            blocked = []
            for address, other in address_assets.items():
                if other.id != by_mac.id:
                    blocked.append(address)
            if blocked:
                conflict = {
                    "reason": "mac_and_ip_disagree",
                    "mac_asset_id": by_mac.id,
                    "blocked_addresses": blocked,
                    "ip_asset_ids": [asset.id for asset in unique_ip_assets.values()],
                }
            return by_mac, conflict
        if len(unique_ip_assets) == 1:
            return next(iter(unique_ip_assets.values())), {}
        if len(unique_ip_assets) > 1:
            chosen = next(iter(unique_ip_assets.values()))
            conflict = {
                "reason": "addresses_map_to_multiple_assets",
                "asset_ids": list(unique_ip_assets),
                "blocked_addresses": [
                    address
                    for address, asset in address_assets.items()
                    if asset.id != chosen.id
                ],
            }
            return chosen, conflict
        return None, {}

    def _ingest_arp(
        self,
        session: Session,
        audit_id: str,
        job_id: str | None,
        sensors: dict[str, Any],
        evidence_reference: str | None,
    ) -> int:
        count = 0
        arp = sensors.get("arp") or {}
        for observation in arp.get("observations") or []:
            data = observation.get("data") or {}
            mac = canonical_mac(data.get("sender_mac"))
            ipv4 = data.get("sender_ipv4")
            addresses = []
            if ipv4:
                try:
                    addresses.append(canonical_ip(ipv4))
                except ValueError:
                    pass
            if not mac and not addresses:
                continue
            self._upsert_identity(
                session,
                audit_id=audit_id,
                job_id=job_id,
                mac=mac,
                addresses=addresses,
                names=[],
                source="arp",
                evidence_reference=evidence_reference,
                state=AssetState.OBSERVED,
            )
            count += 1
        return count

    def _ingest_dhcp(
        self,
        session: Session,
        audit_id: str,
        job_id: str | None,
        sensors: dict[str, Any],
        evidence_reference: str | None,
    ) -> int:
        count = 0
        dhcp = sensors.get("dhcpv4") or sensors.get("dhcp") or {}
        for observation in dhcp.get("observations") or []:
            data = observation.get("data") or {}
            mac = canonical_mac(data.get("client_mac"))
            addresses = []
            for value in (data.get("offered_ip"), data.get("requested_ip")):
                if not value:
                    continue
                try:
                    addresses.append(canonical_ip(value))
                    break
                except ValueError:
                    continue
            names = []
            if data.get("hostname"):
                names.append((data["hostname"], "DHCP", "dhcp"))
            if not mac and not addresses and not names:
                continue
            self._upsert_identity(
                session,
                audit_id=audit_id,
                job_id=job_id,
                mac=mac,
                addresses=addresses,
                names=names,
                source="dhcp",
                evidence_reference=evidence_reference,
                state=AssetState.OBSERVED,
            )
            count += 1
        return count

    def _ingest_naming(
        self,
        session: Session,
        audit_id: str,
        job_id: str | None,
        sensor_name: str,
        sensors: dict[str, Any],
        evidence_reference: str | None,
    ) -> int:
        count = 0
        sensor = sensors.get(sensor_name) or {}
        name_type = {
            "mdns": "mDNS",
            "llmnr": "LLMNR",
            "nbns": "NBNS",
        }[sensor_name]
        for observation in sensor.get("observations") or []:
            data = observation.get("data") or {}
            addresses = []
            for value in data.get("addresses") or []:
                try:
                    addresses.append(canonical_ip(value))
                except ValueError:
                    continue
            metadata = observation.get("metadata") or {}
            if metadata.get("source_ip"):
                try:
                    addresses.append(canonical_ip(metadata["source_ip"]))
                except ValueError:
                    pass
            names = []
            for field in ("response_names", "query_names", "names"):
                for name in data.get(field) or []:
                    names.append((name, name_type, sensor_name))
            mac = canonical_mac(metadata.get("source_mac"))
            if not addresses and not names and not mac:
                continue
            self._upsert_identity(
                session,
                audit_id=audit_id,
                job_id=job_id,
                mac=mac,
                addresses=addresses,
                names=names,
                source=sensor_name,
                evidence_reference=evidence_reference,
                state=AssetState.OBSERVED,
            )
            count += 1
        return count

    def _upsert_identity(
        self,
        session: Session,
        *,
        audit_id: str,
        job_id: str | None,
        mac: str | None,
        addresses: list[tuple[str, int]],
        names: list[tuple[str, str, str]],
        source: str,
        evidence_reference: str | None,
        state: AssetState,
    ) -> AssetModel:
        asset, conflict = self._correlate(
            session,
            audit_id=audit_id,
            mac=mac,
            addresses=addresses,
        )
        now = utc_now()
        if asset is None:
            vendor = self.vendors.lookup(mac)
            asset = AssetModel(
                id=str(uuid.uuid4()),
                audit_id=audit_id,
                state=state.value,
                mac=mac,
                vendor=vendor.vendor,
                vendor_source=vendor.source,
                vendor_database_version=vendor.database_version,
                device_class_hint=DeviceClassHint.UNKNOWN.value,
                device_class_confidence=ConfidenceLevel.UNKNOWN.value,
                first_seen=now,
                last_seen=now,
                metadata_json={},
            )
            session.add(asset)
            session.flush()
        else:
            asset.last_seen = now
            self._merge_state(asset, state)
            if mac and asset.mac is None:
                other = self._asset_by_mac(session, audit_id, mac)
                if other is None or other.id == asset.id:
                    asset.mac = mac
                    vendor = self.vendors.lookup(mac)
                    if vendor.vendor and not asset.vendor:
                        asset.vendor = vendor.vendor
                        asset.vendor_source = vendor.source
                        asset.vendor_database_version = (
                            vendor.database_version
                        )
        if conflict:
            self._observe(
                session,
                audit_id=audit_id,
                asset_id=asset.id,
                job_id=job_id,
                observation_type="identity_conflict",
                source=source,
                evidence_reference=evidence_reference,
                data=conflict,
            )
        blocked = set(conflict.get("blocked_addresses", []) if conflict else [])
        primary_set = bool(asset.addresses)
        for address, family in addresses:
            if address in blocked:
                continue
            self._upsert_address(
                session,
                audit_id=audit_id,
                asset=asset,
                address=address,
                family=family,
                source=source,
                now=now,
                is_primary=not primary_set,
            )
            primary_set = True
        for name, name_type, name_source in names:
            self._upsert_name(
                session,
                audit_id=audit_id,
                asset=asset,
                name=name,
                name_type=name_type,
                source=name_source,
                now=now,
            )
        return asset

    def _upsert_address(
        self,
        session: Session,
        *,
        audit_id: str,
        asset: AssetModel,
        address: str,
        family: int,
        source: str,
        now: datetime,
        is_primary: bool,
    ) -> None:
        existing = session.scalar(
            select(AssetAddressModel).where(
                AssetAddressModel.audit_id == audit_id,
                AssetAddressModel.address == address,
            )
        )
        confidence = SOURCE_CONFIDENCE.get(source, ConfidenceLevel.MEDIUM)
        if existing is None:
            session.add(
                AssetAddressModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    asset_id=asset.id,
                    address=address,
                    family=family,
                    is_primary=is_primary,
                    first_seen=now,
                    last_seen=now,
                    source=source,
                    confidence=confidence.value,
                )
            )
            return
        if existing.asset_id != asset.id:
            self._observe(
                session,
                audit_id=audit_id,
                asset_id=asset.id,
                job_id=None,
                observation_type="address_owned_by_other_asset",
                source=source,
                evidence_reference=None,
                data={
                    "address": address,
                    "owner_asset_id": existing.asset_id,
                },
            )
            existing.last_seen = now
            return
        existing.last_seen = now
        if is_primary:
            existing.is_primary = True

    def _upsert_name(
        self,
        session: Session,
        *,
        audit_id: str,
        asset: AssetModel,
        name: str,
        name_type: str,
        source: str,
        now: datetime,
    ) -> None:
        cleaned = name.strip().rstrip(".")
        if not cleaned:
            return
        existing = session.scalar(
            select(AssetNameModel).where(
                AssetNameModel.asset_id == asset.id,
                AssetNameModel.name == cleaned,
                AssetNameModel.name_type == name_type,
                AssetNameModel.source == source,
            )
        )
        confidence = SOURCE_CONFIDENCE.get(source, ConfidenceLevel.MEDIUM)
        if existing is None:
            session.add(
                AssetNameModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    asset_id=asset.id,
                    name=cleaned,
                    name_type=name_type,
                    source=source,
                    confidence=confidence.value,
                    first_seen=now,
                    last_seen=now,
                )
            )
            return
        existing.last_seen = now

    def _upsert_service(
        self,
        session: Session,
        *,
        audit_id: str,
        asset: AssetModel,
        host_port,
        source: str,
        now: datetime,
    ) -> None:
        existing = session.scalar(
            select(ServiceModel).where(
                ServiceModel.asset_id == asset.id,
                ServiceModel.protocol == host_port.protocol,
                ServiceModel.port == host_port.port,
            )
        )
        service = host_port.service
        confidence = _service_confidence(service)
        values = {
            "state": host_port.state,
            "reason": host_port.reason,
            "service_name": service.name if service else None,
            "product": service.product if service else None,
            "version": service.version if service else None,
            "extra_info": service.extra_info if service else None,
            "tunnel": service.tunnel if service else None,
            "cpe": list(service.cpe) if service else [],
            "banner": service.banner if service else None,
            "method": service.method if service else None,
            "confidence": confidence.value,
            "source": source,
            "last_seen": now,
        }
        if existing is None:
            session.add(
                ServiceModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    asset_id=asset.id,
                    protocol=host_port.protocol,
                    port=host_port.port,
                    first_seen=now,
                    **values,
                )
            )
            return
        for key, value in values.items():
            if key in {"service_name", "product", "version", "extra_info", "cpe", "banner"}:
                current = getattr(existing, key)
                if current and value and current != value:
                    metadata = dict(asset.metadata_json or {})
                    conflicts = list(metadata.get("service_conflicts") or [])
                    conflicts.append(
                        {
                            "protocol": host_port.protocol,
                            "port": host_port.port,
                            "field": key,
                            "existing": current,
                            "observed": value,
                        }
                    )
                    metadata["service_conflicts"] = conflicts[-20:]
                    asset.metadata_json = metadata
                    if _confidence_rank(confidence) <= _confidence_rank(
                        ConfidenceLevel(existing.confidence)
                    ):
                        continue
            setattr(existing, key, value)

    def _apply_os_hint(
        self,
        session: Session,
        asset: AssetModel,
        host: NmapHost,
        job_id: str | None,
        evidence_reference: str | None,
    ) -> None:
        if not host.os_matches:
            return
        best = max(host.os_matches, key=lambda item: item.accuracy)
        if asset.os_name and asset.os_name != best.name:
            self._observe(
                session,
                audit_id=asset.audit_id,
                asset_id=asset.id,
                job_id=job_id,
                observation_type="os_hint_conflict",
                source="nmap",
                evidence_reference=evidence_reference,
                data={
                    "existing": {
                        "name": asset.os_name,
                        "family": asset.os_family,
                        "accuracy": asset.os_accuracy,
                    },
                    "observed": {
                        "name": best.name,
                        "family": best.family,
                        "accuracy": best.accuracy,
                    },
                },
            )
            if (asset.os_accuracy or 0) >= best.accuracy:
                return
        asset.os_family = best.family
        asset.os_name = best.name
        asset.os_generation = best.generation
        asset.os_accuracy = best.accuracy
        metadata = dict(asset.metadata_json or {})
        metadata["os_hint"] = {
            "family": best.family,
            "name": best.name,
            "generation": best.generation,
            "accuracy": best.accuracy,
            "source": "nmap",
            "confidence": _os_confidence(best.accuracy).value,
        }
        if host.uptime_seconds is not None:
            metadata["uptime_seconds"] = host.uptime_seconds
        if host.network_distance is not None:
            metadata["network_distance"] = host.network_distance
        asset.metadata_json = metadata

    def _classify_asset(self, session: Session, asset: AssetModel) -> None:
        services = list(asset.services)
        if not services:
            services = session.scalars(
                select(ServiceModel).where(ServiceModel.asset_id == asset.id)
            ).all()
        names = list(asset.names)
        if not names:
            names = session.scalars(
                select(AssetNameModel).where(AssetNameModel.asset_id == asset.id)
            ).all()
        hint, confidence, sources = classify_device(
            os_family=asset.os_family,
            os_name=asset.os_name,
            vendor=asset.vendor,
            open_ports={
                (item.protocol, item.port)
                for item in services
                if item.state == "open"
            },
            name_sources={item.source for item in names},
        )
        asset.device_class_hint = hint.value
        asset.device_class_confidence = confidence.value
        metadata = dict(asset.metadata_json or {})
        metadata["device_class"] = {
            "hint": hint.value,
            "confidence": confidence.value,
            "sources": sources,
        }
        asset.metadata_json = metadata

    def _refresh_classifications(
        self,
        session: Session,
        audit_id: str,
    ) -> None:
        assets = session.scalars(
            select(AssetModel)
            .where(AssetModel.audit_id == audit_id)
            .options(
                selectinload(AssetModel.services),
                selectinload(AssetModel.names),
            )
        ).all()
        for asset in assets:
            self._classify_asset(session, asset)

    def _asset_by_mac(
        self,
        session: Session,
        audit_id: str,
        mac: str | None,
    ) -> AssetModel | None:
        if not mac:
            return None
        return session.scalar(
            select(AssetModel).where(
                AssetModel.audit_id == audit_id,
                AssetModel.mac == mac,
            )
        )

    def _asset_by_address(
        self,
        session: Session,
        audit_id: str,
        address: str,
    ) -> AssetModel | None:
        row = session.scalar(
            select(AssetAddressModel).where(
                AssetAddressModel.audit_id == audit_id,
                AssetAddressModel.address == address,
            )
        )
        if row is None:
            return None
        return session.get(AssetModel, row.asset_id)

    @staticmethod
    def _merge_state(asset: AssetModel, observed: AssetState) -> None:
        current = AssetState(asset.state)
        rank = {
            AssetState.UNKNOWN: 0,
            AssetState.UNRESPONSIVE: 1,
            AssetState.OBSERVED: 2,
            AssetState.RESPONSIVE: 3,
        }
        if observed == AssetState.UNRESPONSIVE and current == AssetState.RESPONSIVE:
            asset.state = observed.value
            return
        if rank[observed] >= rank[current]:
            asset.state = observed.value

    def _observe(
        self,
        session: Session,
        *,
        audit_id: str,
        asset_id: str | None,
        job_id: str | None,
        observation_type: str,
        source: str,
        evidence_reference: str | None,
        data: dict[str, Any],
    ) -> None:
        session.add(
            AssetObservationModel(
                id=str(uuid.uuid4()),
                audit_id=audit_id,
                asset_id=asset_id,
                job_id=job_id,
                observation_type=observation_type,
                source=source,
                evidence_reference=evidence_reference,
                data=data,
            )
        )

    @staticmethod
    def _scope_record(model: ConfirmedScopeModel) -> ConfirmedScopeRecord:
        return ConfirmedScopeRecord(
            id=model.id,
            audit_id=model.audit_id,
            created_at=model.created_at,
            activated_at=model.activated_at,
            profile=ActiveProfile(model.profile),
            interface=model.interface,
            targets=list(model.targets),
            address_families=list(model.address_families),
            address_count=model.address_count,
            route_context=model.route_context,
            timing_policy=model.timing_policy,
            actor=model.actor,
            snapshot_hash=model.snapshot_hash,
        )

    @staticmethod
    def _asset_record(
        model: AssetModel,
        *,
        include_services: bool,
    ) -> AssetRecord:
        return AssetRecord(
            id=model.id,
            audit_id=model.audit_id,
            state=AssetState(model.state),
            mac=model.mac,
            vendor=model.vendor,
            vendor_source=model.vendor_source,
            vendor_database_version=model.vendor_database_version,
            device_class_hint=DeviceClassHint(model.device_class_hint),
            device_class_confidence=ConfidenceLevel(
                model.device_class_confidence
            ),
            os_family=model.os_family,
            os_name=model.os_name,
            os_generation=model.os_generation,
            os_accuracy=model.os_accuracy,
            first_seen=model.first_seen,
            last_seen=model.last_seen,
            metadata=model.metadata_json or {},
            addresses=[
                AssetAddressRecord(
                    id=item.id,
                    asset_id=item.asset_id,
                    address=item.address,
                    family=item.family,
                    is_primary=item.is_primary,
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                    source=item.source,
                    confidence=ConfidenceLevel(item.confidence),
                )
                for item in sorted(
                    model.addresses,
                    key=lambda item: (item.family, item.address),
                )
            ],
            names=[
                AssetNameRecord(
                    id=item.id,
                    asset_id=item.asset_id,
                    name=item.name,
                    name_type=item.name_type,
                    source=item.source,
                    confidence=ConfidenceLevel(item.confidence),
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                )
                for item in sorted(
                    model.names,
                    key=lambda item: (item.source, item.name),
                )
            ],
            services=(
                [
                    InventoryService._service_record(item)
                    for item in sorted(
                        model.services,
                        key=lambda item: (item.protocol, item.port),
                    )
                ]
                if include_services
                else []
            ),
        )

    @staticmethod
    def _service_record(model: ServiceModel) -> ServiceRecord:
        return ServiceRecord(
            id=model.id,
            audit_id=model.audit_id,
            asset_id=model.asset_id,
            protocol=model.protocol,
            port=model.port,
            state=model.state,
            reason=model.reason,
            service_name=model.service_name,
            product=model.product,
            version=model.version,
            extra_info=model.extra_info,
            tunnel=model.tunnel,
            cpe=list(model.cpe or []),
            banner=model.banner,
            method=model.method,
            confidence=ConfidenceLevel(model.confidence),
            source=model.source,
            first_seen=model.first_seen,
            last_seen=model.last_seen,
        )


def scope_snapshot_hash(
    *,
    profile: ActiveProfile,
    interface: str,
    targets: list[str],
) -> str:
    payload = json.dumps(
        {
            "profile": profile.value,
            "interface": interface,
            "targets": targets,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _host_state(status: str) -> AssetState:
    if status == "up":
        return AssetState.RESPONSIVE
    if status == "down":
        return AssetState.UNRESPONSIVE
    return AssetState.UNKNOWN


def _os_confidence(accuracy: int) -> ConfidenceLevel:
    if accuracy >= 95:
        return ConfidenceLevel.HIGH
    if accuracy >= 85:
        return ConfidenceLevel.MEDIUM
    if accuracy >= 70:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.HINT


def _service_confidence(service) -> ConfidenceLevel:
    if service is None:
        return ConfidenceLevel.LOW
    if service.confidence is not None:
        if service.confidence >= 10:
            return ConfidenceLevel.HIGH
        if service.confidence >= 7:
            return ConfidenceLevel.MEDIUM
        if service.confidence >= 4:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.HINT
    if service.method == "probed":
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _confidence_rank(level: ConfidenceLevel) -> int:
    return {
        ConfidenceLevel.UNKNOWN: 0,
        ConfidenceLevel.HINT: 1,
        ConfidenceLevel.LOW: 2,
        ConfidenceLevel.MEDIUM: 3,
        ConfidenceLevel.HIGH: 4,
        ConfidenceLevel.CONFIRMED: 5,
    }[level]
