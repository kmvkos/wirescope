"""Logical network topology built from persisted WireScope evidence."""

from topology.builder import TopologySourceError
from topology.completeness import decorate_completeness
from topology.findings import decorate_findings
from topology.global_view import build_global_topology as _build_global_topology
from topology.presentation import decorate_presentation
from topology.routing import decorate_global_routing_topology, decorate_routed_topology
from topology.segmented import build_topology as _build_segmented_topology
from topology.snmp import decorate_global_snmp_topology, decorate_snmp_topology
from topology.snmp_extended import (
    decorate_global_snmp_extended_topology,
    decorate_snmp_extended_topology,
)
from topology.snmp_role_guard import guard_snmp_router_roles
from topology.source_health import decorate_source_health
from topology.upstream import decorate_global_upstream_topology, decorate_upstream_topology


def _decorate_operator_view(topology):
    topology = decorate_presentation(topology)
    return decorate_completeness(topology)


def build_topology(services, audit_id: str, *, traffic_analysis_job_id: str | None = None):
    topology = _build_segmented_topology(
        services,
        audit_id,
        traffic_analysis_job_id=traffic_analysis_job_id,
    )
    topology = decorate_routed_topology(topology)
    topology = decorate_upstream_topology(services, audit_id, topology)
    topology = decorate_snmp_topology(services, audit_id, topology)
    topology = decorate_snmp_extended_topology(services, audit_id, topology)
    topology = guard_snmp_router_roles(topology)
    topology = decorate_findings(services, audit_id, topology)
    topology = decorate_source_health(services, topology, audit_ids=[audit_id])
    return _decorate_operator_view(topology)


def build_global_topology(services, *, limit: int = 100):
    topology = decorate_global_routing_topology(
        _build_global_topology(services, limit=limit)
    )
    topology = decorate_global_upstream_topology(services, topology)
    topology = decorate_global_snmp_topology(services, topology)
    topology = decorate_global_snmp_extended_topology(services, topology)
    topology = guard_snmp_router_roles(topology)
    audit_ids = [
        str(item.get("id"))
        for item in topology.get("audits") or []
        if item.get("id")
    ]
    topology = decorate_source_health(services, topology, audit_ids=audit_ids)
    return _decorate_operator_view(topology)


__all__ = ["TopologySourceError", "build_topology", "build_global_topology"]
