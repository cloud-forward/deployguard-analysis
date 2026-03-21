"""Typed result contracts for graph builder outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


@runtime_checkable
class GraphNodeLike(Protocol):
    """Minimal node contract required by merge and NetworkX adaptation."""

    id: str
    type: str
    metadata: dict[str, Any]


@runtime_checkable
class GraphEdgeLike(Protocol):
    """Minimal edge contract required by merge and NetworkX adaptation."""

    source: str
    target: str
    type: str
    metadata: dict[str, Any]


MergeableGraphNode = GraphNodeLike
MergeableGraphEdge = GraphEdgeLike


@dataclass
class K8sBuildResult:
    """Kubernetes-only graph output retained for later unified merging."""

    nodes: list[K8sGraphNode] = field(default_factory=list)
    edges: list[K8sGraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AWSBuildResult:
    """AWS-only graph output retained for later unified merging."""

    nodes: list[AWSGraphNode] = field(default_factory=list)
    edges: list[AWSGraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedGraphResult:
    """Merged graph output plus merge-layer metadata and warnings."""

    nodes: list[MergeableGraphNode] = field(default_factory=list)
    edges: list[MergeableGraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def graph_node_identity(node: GraphNodeLike) -> str:
    """Return the stable identity key for merge-time node deduplication."""

    return node.id


def graph_edge_identity(edge: GraphEdgeLike) -> tuple[str, str, str]:
    """Return the stable identity key for merge-time edge deduplication."""

    return edge.source, edge.target, edge.type


def graph_node_attrs(node: GraphNodeLike) -> dict[str, Any]:
    """Normalize the common node shape expected by the NetworkX adapter."""

    return {
        "id": node.id,
        "type": node.type,
        "is_entry_point": getattr(node, "is_entry_point", False),
        "is_crown_jewel": getattr(node, "is_crown_jewel", False),
        "base_risk": getattr(node, "base_risk", 0.0),
        "metadata": dict(getattr(node, "metadata", {}) or {}),
    }


def graph_edge_attrs(edge: GraphEdgeLike) -> dict[str, Any]:
    """Normalize the common edge shape expected by the NetworkX adapter."""

    return {
        "source": edge.source,
        "target": edge.target,
        "type": edge.type,
        "metadata": dict(edge.metadata or {}),
    }


def unpack_build_result(
    result: K8sBuildResult | AWSBuildResult | UnifiedGraphResult,
) -> tuple[list[Any], list[Any]]:
    """Transitional adapter for legacy callers that still expect (nodes, edges)."""

    return result.nodes, result.edges
