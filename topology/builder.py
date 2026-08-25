"""Build a logical topology from persisted WireScope evidence only.

The topology deliberately distinguishes confirmed, observed, and inferred
relationships.  It never invents a physical switch hop merely because two
assets share a subnet.  A retained PCAP analysis may be overlaid explicitly;
it is never selected implicitly.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
from typing import Any

from jobs.errors import JobExecutionError
from jobs.models import JobStatus
from jobs.service import EntityNotFound
from reports.passive import project_passive
from reports.sources import load_report_source


class TopologySourceError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _safe_ip(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _is_multicast_or_broadcast(value: str) -> bool:
    if value.lower() == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_multicast or str(address) == "255.255.255.255")


def _confidence_rank(value: str) -> int:
    return {"inferred": 1, "observed": 2, "confirmed": 3}.get(value, 0)


def _merge_unique(current: list[Any], incoming: list[Any]) -> list[Any]:
    result = list(current)
    for item in incoming:
        if item not in result:
            result.append(item)
    return result


def _asset_label(asset: dict[str, Any]) -> str:
    names = asset.get("names") or []
    addresses = asset.get("addresses") or []
    return str(
        (names[0] if names else None)
        or (addresses[0] if addresses else None)
        or asset.get("mac")
        or asset.get("id")
        or "asset"
    )


def _node_id_for_endpoint(endpoint: str) -> str:
    prefix = "group" if _is_multicast_or_broadcast(endpoint) else "endpoint"
    return f"{prefix}:{endpoint}"


def _load_traffic_document(services, job_id: str) -> tuple[Any, dict[str, Any]]:
    try:
        job = services.jobs.get_job(job_id)
    except EntityNotFound as exc:
        raise TopologySourceError(f"Traffic analysis not found: {job_id}") from exc
    if job.type != "traffic_analysis":
        raise TopologySourceError("Selected overlay is not a traffic analysis job")
    if job.status != JobStatus.COMPLETED or not job.result_reference:
        raise TopologySourceError("Selected traffic analysis is not completed")
    try:
        artifact = services.jobs.artifact(job.result_reference)
        if artifact.job_id != job.id or artifact.artifact_type != "traffic_analysis_result":
            raise TopologySourceError("Traffic analysis result reference is inconsistent")
        document = services.evidence.read_json(artifact)
    except EntityNotFound as exc:
        raise TopologySourceError("Traffic analysis result artifact was not found") from exc
    except JobExecutionError as exc:
        raise TopologySourceError("Traffic analysis result could not be read") from exc
    return job, document


def build_topology(
    services,
    audit_id: str,
    *,
    traffic_analysis_job_id: str | None = None,
) -> dict[str, Any]:
    """Build a topology view without generating network traffic."""
    audit = services.jobs.get_audit(audit_id)
    report_source = load_report_source(
        audit=audit,
        database=services.database,
        inventory=services.inventory,
        findings=services.findings,
        evidence_store=services.evidence,
    )
    passive = project_passive(
        environment=report_source.environment,
        audit_interface=audit.interface,
        audit_summary=dict(audit.summary or {}),
        passive_result=report_source.passive_result,
    ).model_dump(mode="json")
    latest_scope = services.inventory.latest_scope(audit_id)

    assets = [item.model_dump(mode="json") for item in report_source.assets]
    services_rows = [item.model_dump(mode="json") for item in report_source.services]
    topology = assemble_topology(
        audit={
            "id": audit.id,
            "profile": audit.profile,
            "interface": audit.interface,
            "status": audit.status.value,
            "scope": dict(audit.scope or {}),
        },
        assets=assets,
        services=services_rows,
        environment=report_source.environment or {},
        passive=passive,
        confirmed_scope=(latest_scope.model_dump(mode="json") if latest_scope else None),
        traffic_analysis=None,
    )

    if traffic_analysis_job_id:
        traffic_job, traffic_document = _load_traffic_document(
            services, traffic_analysis_job_id
        )
        topology = assemble_topology(
            audit=topology["audit"],
            assets=assets,
            services=services_rows,
            environment=report_source.environment or {},
            passive=passive,
            confirmed_scope=(latest_scope.model_dump(mode="json") if latest_scope else None),
            traffic_analysis={
                "job_id": traffic_job.id,
                "audit_id": traffic_job.audit_id,
                "document": traffic_document,
            },
        )
    topology["warnings"] = _merge_unique(
        list(topology.get("warnings") or []),
        list(report_source.warnings or []),
    )
    return topology


def assemble_topology(
    *,
    audit: dict[str, Any],
    assets: list[dict[str, Any]],
    services: list[dict[str, Any]],
    environment: dict[str, Any],
    passive: dict[str, Any],
    confirmed_scope: dict[str, Any] | None,
    traffic_analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    groups: list[dict[str, Any]] = []
    aliases: dict[str, str] = {}
    warnings: list[str] = []

    service_by_asset: dict[str, list[dict[str, Any]]] = {}
    for service in services:
        service_by_asset.setdefault(str(service.get("asset_id") or ""), []).append(service)

    def add_node(node_id: str, **values: Any) -> dict[str, Any]:
        existing = nodes.get(node_id)
        if existing is None:
            existing = {
                "id": node_id,
                "kind": values.pop("kind", "endpoint"),
                "label": values.pop("label", node_id),
                "roles": [],
                "addresses": [],
                "names": [],
                "provenance": [],
                "confidence": values.pop("confidence", "inferred"),
            }
            nodes[node_id] = existing
        for list_key in ("roles", "addresses", "names", "provenance"):
            incoming = values.pop(list_key, None)
            if incoming:
                existing[list_key] = _merge_unique(existing.get(list_key) or [], list(incoming))
        incoming_confidence = values.pop("confidence", None)
        if incoming_confidence and _confidence_rank(incoming_confidence) > _confidence_rank(existing.get("confidence", "")):
            existing["confidence"] = incoming_confidence
        for key, value in values.items():
            if value is not None and value != "":
                existing[key] = value
        return existing

    def add_edge(
        a: str,
        b: str,
        *,
        relation: str,
        confidence: str,
        provenance: str,
        **metadata: Any,
    ) -> None:
        if not a or not b or a == b:
            return
        left, right = sorted((a, b))
        key = (left, right, relation)
        edge = edges.get(key)
        if edge is None:
            edge = {
                "id": f"edge:{len(edges) + 1}",
                "source": a,
                "target": b,
                "relation": relation,
                "confidence": confidence,
                "provenance": [provenance],
            }
            edges[key] = edge
        else:
            edge["provenance"] = _merge_unique(edge.get("provenance") or [], [provenance])
            if _confidence_rank(confidence) > _confidence_rank(edge.get("confidence", "")):
                edge["confidence"] = confidence
        for key_name, value in metadata.items():
            if value is None:
                continue
            if key_name in {"packets", "bytes", "packets_a_to_b", "packets_b_to_a", "bytes_a_to_b", "bytes_b_to_a"}:
                edge[key_name] = int(edge.get(key_name) or 0) + int(value or 0)
            elif key_name in {"protocols", "ports"}:
                edge[key_name] = _merge_unique(edge.get(key_name) or [], list(value or []))
            else:
                edge[key_name] = value

    for asset in assets:
        asset_id = str(asset.get("id") or "")
        if not asset_id:
            continue
        node_id = f"asset:{asset_id}"
        addresses = [str(value) for value in (asset.get("addresses") or []) if value]
        names = [str(value) for value in (asset.get("names") or []) if value]
        node_services = service_by_asset.get(asset_id, [])
        node = add_node(
            node_id,
            kind="asset",
            label=_asset_label(asset),
            asset_id=asset_id,
            state=asset.get("state"),
            mac=asset.get("mac"),
            vendor=asset.get("vendor"),
            device_class=asset.get("device_class_hint"),
            os_name=asset.get("os_name"),
            addresses=addresses,
            names=names,
            services=[
                {
                    "protocol": item.get("protocol"),
                    "port": item.get("port"),
                    "state": item.get("state"),
                    "name": item.get("service_name"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                }
                for item in node_services[:64]
            ],
            provenance=["inventory"],
            confidence="confirmed" if asset.get("state") == "responsive" else "observed",
        )
        if asset.get("device_class_hint") == "network-device-like":
            node["roles"] = _merge_unique(node.get("roles") or [], ["network-device"])
        for alias in addresses + names:
            aliases[alias.lower()] = node_id
        if asset.get("mac"):
            aliases[str(asset["mac"]).lower()] = node_id

    interface = _text(audit.get("interface")) or "unknown"
    appliance_id = f"wirescope:{interface}"
    appliance_addresses: list[str] = []
    for item in environment.get("interfaces") or []:
        if isinstance(item, dict) and item.get("name") == interface:
            appliance_addresses.extend(str(value) for value in (item.get("ipv4") or []) if value)
            appliance_addresses.extend(str(value) for value in (item.get("ipv6") or []) if value)
    add_node(
        appliance_id,
        kind="wirescope",
        label=f"WireScope · {interface}",
        roles=["sensor"],
        addresses=appliance_addresses,
        provenance=["environment"],
        confidence="confirmed",
    )
    for address in appliance_addresses:
        aliases.setdefault(address.split("/", 1)[0].lower(), appliance_id)

    def resolve_endpoint(endpoint: str, *, role: str | None = None, provenance: str = "topology") -> str:
        normalized = endpoint.lower()
        node_id = aliases.get(normalized)
        if node_id:
            if role:
                nodes[node_id]["roles"] = _merge_unique(nodes[node_id].get("roles") or [], [role])
            return node_id
        node_id = _node_id_for_endpoint(endpoint)
        kind = "multicast-group" if node_id.startswith("group:") else "endpoint"
        roles = [role] if role else []
        add_node(
            node_id,
            kind=kind,
            label=endpoint,
            addresses=[endpoint] if _safe_ip(endpoint) else [],
            names=[] if _safe_ip(endpoint) else [endpoint],
            roles=roles,
            provenance=[provenance],
            confidence="observed" if provenance in {"pcap", "dhcp", "arp"} else "inferred",
        )
        aliases[normalized] = node_id
        return node_id

    gateway_sources: list[tuple[str, str, str]] = []
    default_route = environment.get("default_route")
    if isinstance(default_route, dict):
        gateway = _safe_ip(default_route.get("gateway"))
        if gateway:
            gateway_sources.append((gateway, "default-route", "confirmed"))
    if confirmed_scope:
        route_context = confirmed_scope.get("route_context") or {}
        if isinstance(route_context, dict):
            gateway = _safe_ip(route_context.get("gateway") or route_context.get("via"))
            if gateway:
                gateway_sources.append((gateway, "confirmed-scope-route", "confirmed"))
    dhcp = passive.get("dhcp") or {}
    for value in dhcp.get("routers") or []:
        gateway = _safe_ip(value)
        if gateway:
            gateway_sources.append((gateway, "dhcp-router", "observed"))

    for gateway, provenance, confidence in gateway_sources:
        gateway_id = resolve_endpoint(gateway, role="gateway", provenance=provenance)
        add_edge(
            appliance_id,
            gateway_id,
            relation="default_gateway",
            confidence=confidence,
            provenance=provenance,
        )

    for server in (dhcp.get("servers") or []):
        address = _safe_ip(server)
        if not address:
            continue
        server_id = resolve_endpoint(address, role="dhcp-server", provenance="dhcp")
        add_edge(
            appliance_id,
            server_id,
            relation="dhcp_observed",
            confidence="observed",
            provenance="dhcp",
        )

    for neighbor in passive.get("neighbors") or []:
        if not isinstance(neighbor, dict):
            continue
        protocol = str(neighbor.get("protocol") or "neighbor").upper()
        label = _text(neighbor.get("name")) or _text(neighbor.get("port_id")) or f"{protocol} neighbor"
        alias_match = aliases.get(label.lower())
        if alias_match:
            neighbor_id = alias_match
            nodes[neighbor_id]["roles"] = _merge_unique(nodes[neighbor_id].get("roles") or [], ["network-neighbor"])
        else:
            neighbor_id = f"neighbor:{protocol.lower()}:{label.lower()}:{neighbor.get('port_id') or ''}"
            add_node(
                neighbor_id,
                kind="network-device",
                label=label,
                roles=["network-neighbor"],
                names=[label] if neighbor.get("name") else [],
                port_id=neighbor.get("port_id"),
                native_vlan=neighbor.get("native_vlan"),
                voice_vlan=neighbor.get("voice_vlan"),
                pvid=neighbor.get("pvid"),
                provenance=[protocol.lower()],
                confidence="confirmed",
            )
        add_edge(
            appliance_id,
            neighbor_id,
            relation="layer2_neighbor",
            confidence="confirmed",
            provenance=protocol.lower(),
            port_id=neighbor.get("port_id"),
        )

    stp = passive.get("stp") or {}
    for bridge_id in stp.get("bridge_ids") or []:
        node_id = f"stp-bridge:{bridge_id}"
        add_node(
            node_id,
            kind="network-device",
            label=f"STP bridge {bridge_id}",
            roles=["stp-bridge"],
            provenance=["stp"],
            confidence="observed",
        )
        add_edge(
            appliance_id,
            node_id,
            relation="stp_observed",
            confidence="observed",
            provenance="stp",
        )
    for bridge_id in stp.get("root_bridge_ids") or []:
        node_id = f"stp-bridge:{bridge_id}"
        add_node(
            node_id,
            kind="network-device",
            label=f"STP root {bridge_id}",
            roles=["stp-root"],
            provenance=["stp"],
            confidence="observed",
        )

    subnet_groups: list[dict[str, Any]] = []
    if confirmed_scope:
        for target in confirmed_scope.get("targets") or []:
            try:
                network = ipaddress.ip_network(str(target), strict=False)
            except ValueError:
                continue
            if network.num_addresses <= 1:
                continue
            members: list[str] = []
            for node in nodes.values():
                for address in node.get("addresses") or []:
                    candidate = str(address).split("/", 1)[0]
                    try:
                        if ipaddress.ip_address(candidate) in network:
                            members.append(node["id"])
                            break
                    except ValueError:
                        continue
            subnet_groups.append(
                {
                    "id": f"subnet:{network}",
                    "kind": "subnet",
                    "label": str(network),
                    "members": sorted(set(members)),
                    "confidence": "inferred",
                    "provenance": ["confirmed-scope"],
                }
            )
    groups.extend(subnet_groups)
    for vlan_id in passive.get("tagged_vlan_ids") or []:
        groups.append(
            {
                "id": f"vlan:{vlan_id}",
                "kind": "vlan",
                "label": f"VLAN {vlan_id}",
                "members": [appliance_id],
                "confidence": "observed",
                "provenance": ["802.1q"],
            }
        )

    overlay = None
    if traffic_analysis:
        job_id = str(traffic_analysis.get("job_id") or "")
        document = traffic_analysis.get("document") or {}
        source = document.get("source") or {}
        overlay_interface = _text(source.get("interface"))
        if overlay_interface and interface != "unknown" and overlay_interface != interface:
            warnings.append(
                f"PCAP overlay captured on {overlay_interface}, while audit interface is {interface}. The operator selected this overlay explicitly; interpret correlations with caution."
            )
        graph = document.get("communications_graph") or {}
        for raw_edge in graph.get("edges") or []:
            if not isinstance(raw_edge, dict):
                continue
            endpoint_a = _text(raw_edge.get("endpoint_a"))
            endpoint_b = _text(raw_edge.get("endpoint_b"))
            if not endpoint_a or not endpoint_b:
                continue
            a = resolve_endpoint(endpoint_a, provenance="pcap")
            b = resolve_endpoint(endpoint_b, provenance="pcap")
            protocols = [
                str(item.get("name"))
                for item in (raw_edge.get("protocols") or [])
                if isinstance(item, dict) and item.get("name")
            ]
            ports = [
                str(item.get("port"))
                for item in (raw_edge.get("ports") or [])
                if isinstance(item, dict) and item.get("port")
            ]
            add_edge(
                a,
                b,
                relation="communication",
                confidence="observed",
                provenance="pcap",
                packets=raw_edge.get("packets") or 0,
                bytes=raw_edge.get("bytes") or 0,
                packets_a_to_b=raw_edge.get("packets_a_to_b") or 0,
                packets_b_to_a=raw_edge.get("packets_b_to_a") or 0,
                bytes_a_to_b=raw_edge.get("bytes_a_to_b") or 0,
                bytes_b_to_a=raw_edge.get("bytes_b_to_a") or 0,
                protocols=protocols,
                ports=ports,
                first_seen=raw_edge.get("first_seen"),
                last_seen=raw_edge.get("last_seen"),
            )
        overlay = {
            "traffic_analysis_job_id": job_id,
            "capture_audit_id": traffic_analysis.get("audit_id"),
            "capture_job_id": source.get("capture_job_id"),
            "interface": overlay_interface,
            "frame_count": (document.get("summary") or {}).get("frame_count"),
            "duration_seconds": (document.get("summary") or {}).get("duration_seconds"),
            "analyzer_version": document.get("analyzer_version"),
        }

    edge_rows = list(edges.values())
    relation_counts = Counter(item["relation"] for item in edge_rows)
    confidence_counts = Counter(item["confidence"] for item in edge_rows)
    node_kind_counts = Counter(item["kind"] for item in nodes.values())

    return {
        "schema": "network-topology",
        "schema_version": 1,
        "generated_at": _utc_now(),
        "audit": {
            "id": audit.get("id"),
            "profile": audit.get("profile"),
            "interface": audit.get("interface"),
            "status": audit.get("status"),
            "scope": audit.get("scope") or {},
        },
        "overlay": overlay,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edge_rows),
            "groups": len(groups),
            "node_kinds": dict(node_kind_counts),
            "relations": dict(relation_counts),
            "confidence": dict(confidence_counts),
        },
        "nodes": list(nodes.values()),
        "edges": edge_rows,
        "groups": groups,
        "warnings": warnings,
        "principles": {
            "confirmed": "Direct structured evidence or local configuration (for example LLDP/CDP/default route).",
            "observed": "Relationship or endpoint was actually seen in retained network evidence such as PCAP/DHCP/STP.",
            "inferred": "Logical grouping derived conservatively from confirmed scope/address membership; not a physical-link claim.",
        },
    }
