"""Logical network topology built from persisted WireScope evidence."""

from topology.builder import TopologySourceError
from topology.routing import decorate_global_routing_topology, decorate_routed_topology
from topology.segmented import (
    build_global_topology as _build_global_topology,
    build_topology as _build_segmented_topology,
)


def build_topology(services, audit_id: str, *, traffic_analysis_job_id: str | None = None):
    topology = _build_segmented_topology(
        services,
        audit_id,
        traffic_analysis_job_id=traffic_analysis_job_id,
    )
    return decorate_routed_topology(topology)


def build_global_topology(services, *, limit: int = 100):
    return decorate_global_routing_topology(
        _build_global_topology(services, limit=limit)
    )


__all__ = ["TopologySourceError", "build_topology", "build_global_topology"]
