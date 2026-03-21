"""Minimal unified graph builder for typed domain results."""

from __future__ import annotations

from src.graph.builders.build_result_types import (
    AWSBuildResult,
    K8sBuildResult,
    MergeableGraphEdge,
    MergeableGraphNode,
    UnifiedGraphResult,
    graph_edge_identity,
    graph_node_identity,
)


class UnifiedGraphBuilder:
    """Merges typed K8s and AWS graph outputs without inventing relationships."""

    def build(
        self,
        k8s_result: K8sBuildResult,
        aws_result: AWSBuildResult,
    ) -> UnifiedGraphResult:
        nodes = self._merge_nodes(k8s_result.nodes, aws_result.nodes)
        edges = self._merge_edges(k8s_result.edges, aws_result.edges)
        warnings = self._dangling_edge_warnings(nodes, edges)

        return UnifiedGraphResult(
            nodes=nodes,
            edges=edges,
            metadata={
                "sources": ["k8s", "aws"],
                "k8s": dict(k8s_result.metadata),
                "aws": dict(aws_result.metadata),
                "dangling_edge_count": len(warnings),
            },
            warnings=warnings,
        )

    def _merge_nodes(
        self,
        k8s_nodes: list[MergeableGraphNode],
        aws_nodes: list[MergeableGraphNode],
    ) -> list[MergeableGraphNode]:
        merged: list[MergeableGraphNode] = []
        seen_ids: set[str] = set()

        for node in [*k8s_nodes, *aws_nodes]:
            node_id = graph_node_identity(node)
            if node_id in seen_ids:
                continue
            seen_ids.add(node_id)
            merged.append(node)

        return merged

    def _merge_edges(
        self,
        k8s_edges: list[MergeableGraphEdge],
        aws_edges: list[MergeableGraphEdge],
    ) -> list[MergeableGraphEdge]:
        merged: list[MergeableGraphEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()

        for edge in [*k8s_edges, *aws_edges]:
            edge_key = graph_edge_identity(edge)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            merged.append(edge)

        return merged

    def _dangling_edge_warnings(
        self,
        nodes: list[MergeableGraphNode],
        edges: list[MergeableGraphEdge],
    ) -> list[str]:
        node_ids = {node.id for node in nodes}
        warnings: list[str] = []

        for edge in edges:
            missing = []
            if edge.source not in node_ids:
                missing.append(f"missing source node: {edge.source}")
            if edge.target not in node_ids:
                missing.append(f"missing target node: {edge.target}")
            if missing:
                warnings.append(
                    f"Dangling edge detected for {edge.source} -> {edge.target} ({edge.type}): "
                    + ", ".join(missing)
                )

        return warnings
