"""Tests for graph builder result contract wrappers."""

from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import (
    AWSBuildResult,
    K8sBuildResult,
    UnifiedGraphResult,
)
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


def test_k8s_build_result_carries_nodes_edges_and_merge_metadata():
    result = K8sBuildResult(
        nodes=[
            K8sGraphNode(
                id="pod:production:api",
                type="pod",
                is_entry_point=True,
                metadata={"namespace": "production"},
            )
        ],
        edges=[
            K8sGraphEdge(
                source="ingress:production:public",
                target="pod:production:api",
                type="routes_to",
                metadata={"source_domain": "k8s"},
            )
        ],
        metadata={
            "graph_id": "k8s-scan-001",
            "scan_id": "k8s-scan-001",
            "cluster_id": "cluster-a",
        },
    )

    assert [node.id for node in result.nodes] == ["pod:production:api"]
    assert [(edge.source, edge.target) for edge in result.edges] == [
        ("ingress:production:public", "pod:production:api")
    ]
    assert result.metadata["scan_id"] == "k8s-scan-001"
    assert result.metadata["cluster_id"] == "cluster-a"


def test_aws_build_result_carries_nodes_edges_and_merge_metadata():
    result = AWSBuildResult(
        nodes=[
            AWSGraphNode(
                id="iam:123456789012:AppRole",
                type="iam_role",
                namespace="123456789012",
                metadata={"arn": "arn:aws:iam::123456789012:role/AppRole"},
            )
        ],
        edges=[
            AWSGraphEdge(
                source="sa:production:api",
                target="iam:123456789012:AppRole",
                type="service_account_assumes_iam_role",
                metadata={"bridge_source": "irsa"},
            )
        ],
        metadata={
            "graph_id": "aws-scan-001-graph",
            "scan_id": "aws-scan-001",
            "account_id": "123456789012",
        },
    )

    assert [node.id for node in result.nodes] == ["iam:123456789012:AppRole"]
    assert [(edge.source, edge.target) for edge in result.edges] == [
        ("sa:production:api", "iam:123456789012:AppRole")
    ]
    assert result.metadata["scan_id"] == "aws-scan-001"
    assert result.metadata["account_id"] == "123456789012"


def test_unified_graph_result_carries_merged_outputs_and_warnings():
    result = UnifiedGraphResult(
        nodes=[
            K8sGraphNode(id="pod:production:api", type="pod"),
            AWSGraphNode(
                id="iam:123456789012:AppRole",
                type="iam_role",
                namespace="123456789012",
            ),
        ],
        edges=[
            K8sGraphEdge(
                source="pod:production:api",
                target="sa:production:api",
                type="uses_service_account",
            ),
            AWSGraphEdge(
                source="sa:production:api",
                target="iam:123456789012:AppRole",
                type="service_account_assumes_iam_role",
            ),
        ],
        metadata={
            "sources": ["k8s", "aws"],
            "dangling_edge_count": 1,
        },
        warnings=[
            "Dangling edge retained during merge validation: sa:production:missing -> iam:123456789012:MissingRole"
        ],
    )

    assert len(result.nodes) == 2
    assert len(result.edges) == 2
    assert result.metadata["sources"] == ["k8s", "aws"]
    assert result.metadata["dangling_edge_count"] == 1
    assert result.warnings == [
        "Dangling edge retained during merge validation: sa:production:missing -> iam:123456789012:MissingRole"
    ]
