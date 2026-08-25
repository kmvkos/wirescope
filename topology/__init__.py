"""Logical network topology built from persisted WireScope evidence."""

from topology.builder import TopologySourceError
from topology.segmented import build_global_topology, build_topology

__all__ = ["TopologySourceError", "build_topology", "build_global_topology"]
