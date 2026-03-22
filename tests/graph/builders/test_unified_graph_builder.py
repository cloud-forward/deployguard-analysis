"""Tests for minimal unified graph builder behavior."""

from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import (
    AWSBuildResult,
    K8sBuildResult,
    UnifiedGraphResult,
)
from src.graph.builders.unified_graph_builder import UnifiedGraphBuilder
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


def make_k8s_result() -> K8sBuildResult:
    return K8sBuildResult(
        nodes=[
            K8sGraphNode(id="pod:production:api", type="pod"),
            K8sGraphNode(id="sa:production:api", type="service_account"),
        ],
        edges=[
            K8sGraphEdge(
                source="pod:production:api",
                target="sa:production:api",
                type="pod_uses_service_account",
            )
        ],
        metadata={
            "graph_id": "k8s-scan-001-graph",
            "scan_id": "k8s-scan-001",
            "cluster_id": "cluster-a",
        },
    )


def make_aws_result() -> AWSBuildResult:
    return AWSBuildResult(
        nodes=[
            AWSGraphNode(
                id="iam:123456789012:AppRole",
                type="iam_role",
                namespace="123456789012",
            ),
            AWSGraphNode(
                id="s3:123456789012:data-bucket",
                type="s3_bucket",
                namespace="123456789012",
            ),
        ],
        edges=[
            AWSGraphEdge(
                source="sa:production:api",
                target="iam:123456789012:AppRole",
                type="service_account_assumes_iam_role",
                metadata={"bridge_source": "irsa"},
            ),
            AWSGraphEdge(
                source="iam:123456789012:AppRole",
                target="s3:123456789012:data-bucket",
                type="iam_role_access_resource",
            ),
        ],
        metadata={
            "graph_id": "aws-scan-001-graph",
            "scan_id": "aws-scan-001",
            "account_id": "123456789012",
        },
    )


def test_build_returns_unified_graph_result():
    result = UnifiedGraphBuilder().build(make_k8s_result(), make_aws_result())

    assert isinstance(result, UnifiedGraphResult)


def test_merge_contains_both_k8s_and_aws_nodes():
    result = UnifiedGraphBuilder().build(make_k8s_result(), make_aws_result())
    node_ids = {node.id for node in result.nodes}

    assert "pod:production:api" in node_ids
    assert "iam:123456789012:AppRole" in node_ids


def test_merge_contains_both_k8s_and_aws_edges():
    result = UnifiedGraphBuilder().build(make_k8s_result(), make_aws_result())
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in result.edges}

    assert (
        "pod:production:api",
        "sa:production:api",
        "pod_uses_service_account",
    ) in edge_triplets
    assert (
        "iam:123456789012:AppRole",
        "s3:123456789012:data-bucket",
        "iam_role_access_resource",
    ) in edge_triplets


def test_obvious_dangling_edges_are_recorded_as_warnings():
    aws_result = make_aws_result()
    aws_result.edges.append(
        AWSGraphEdge(
            source="sa:production:missing",
            target="iam:123456789012:MissingRole",
            type="service_account_assumes_iam_role",
        )
    )

    result = UnifiedGraphBuilder().build(make_k8s_result(), aws_result)

    assert result.metadata["dangling_edge_count"] == 1
    assert len(result.warnings) == 1
    assert "missing source node: sa:production:missing" in result.warnings[0]
    assert "missing target node: iam:123456789012:MissingRole" in result.warnings[0]


def test_cross_domain_edges_from_aws_result_are_preserved_as_is():
    result = UnifiedGraphBuilder().build(make_k8s_result(), make_aws_result())

    edge = next(
        edge for edge in result.edges
        if edge.type == "service_account_assumes_iam_role"
    )
    assert edge.source == "sa:production:api"
    assert edge.target == "iam:123456789012:AppRole"
    assert edge.metadata == {"bridge_source": "irsa"}


def test_unified_merge_preserves_secret_cross_domain_edges_from_aws_result():
    aws_result = make_aws_result()
    aws_result.edges.extend(
        [
            AWSGraphEdge(
                source="secret:production:aws-creds",
                target="iam_user:123456789012:deployer",
                type="secret_contains_aws_credentials",
            ),
            AWSGraphEdge(
                source="secret:production:db-creds",
                target="rds:123456789012:production-db",
                type="secret_contains_credentials",
            ),
        ]
    )

    result = UnifiedGraphBuilder().build(make_k8s_result(), aws_result)
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in result.edges}

    assert (
        "secret:production:aws-creds",
        "iam_user:123456789012:deployer",
        "secret_contains_aws_credentials",
    ) in edge_triplets
    assert (
        "secret:production:db-creds",
        "rds:123456789012:production-db",
        "secret_contains_credentials",
    ) in edge_triplets


def test_unified_metadata_contains_both_domain_metadata():
    result = UnifiedGraphBuilder().build(make_k8s_result(), make_aws_result())

    assert result.metadata["sources"] == ["k8s", "aws"]
    assert result.metadata["k8s"] == {
        "graph_id": "k8s-scan-001-graph",
        "scan_id": "k8s-scan-001",
        "cluster_id": "cluster-a",
    }
    assert result.metadata["aws"] == {
        "graph_id": "aws-scan-001-graph",
        "scan_id": "aws-scan-001",
        "account_id": "123456789012",
    }


def test_duplicate_nodes_and_edges_are_deduplicated_by_identity_triplets():
    k8s_result = make_k8s_result()
    aws_result = make_aws_result()
    aws_result.nodes.append(
        AWSGraphNode(
            id="sa:production:api",
            type="service_account",
            namespace="production",
        )
    )
    aws_result.edges.append(
        AWSGraphEdge(
            source="iam:123456789012:AppRole",
            target="s3:123456789012:data-bucket",
            type="iam_role_access_resource",
            metadata={"duplicate": True},
        )
    )

    result = UnifiedGraphBuilder().build(k8s_result, aws_result)

    assert [node.id for node in result.nodes].count("sa:production:api") == 1
    assert [
        (edge.source, edge.target, edge.type)
        for edge in result.edges
    ].count(("iam:123456789012:AppRole", "s3:123456789012:data-bucket", "iam_role_access_resource")) == 1
