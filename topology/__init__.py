"""Logical network topology built from persisted WireScope evidence."""

from topology.builder import TopologySourceError
from topology.findings import decorate_findings
from topology.global_view import build_global_topology as _build_global_topology
from topology.routing import decorate_global_routing_topology, decorate_routed_topology
from topology.segmented import build_topology as _build_segmented_topology
from topology.snmp import decorate_global_snmp_topology, decorate_snmp_topology
from topology.upstream import decorate_global_upstream_topology, decorate_upstream_topology


def build_topology(services, audit_id: str, *, traffic_analysis_job_id: str | None = None):
    topology = _build_segmented_topology(
        services,
        audit_id,
        traffic_analysis_job_id=traffic_analysis_job_id,
    )
    topology = decorate_routed_topology(topology)
    topology = decorate_upstream_topology(services, audit_id, topology)
    topology = decorate_snmp_topology(services, audit_id, topology)
    return decorate_findings(services, audit_id, topology)


def build_global_topology(services, *, limit: int = 100):
    topology = decorate_global_routing_topology(
        _build_global_topology(services, limit=limit)
    )
    topology = decorate_global_upstream_topology(services, topology)
    return decorate_global_snmp_topology(services, topology)


__all__ = ["TopologySourceError", "build_topology", "build_global_topology"]
