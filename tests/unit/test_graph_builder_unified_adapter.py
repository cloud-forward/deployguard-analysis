import pytest

from app.core.graph_builder import GraphBuilder
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import UnifiedGraphResult
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


@pytest.mark.asyncio
async def test_build_from_unified_result_supports_k8s_only_graph():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[
                K8sGraphNode(id="ingress:prod:web", type="ingress"),
                K8sGraphNode(id="service:prod:web", type="service"),
            ],
            edges=[
                K8sGraphEdge(
                    source="ingress:prod:web",
                    target="service:prod:web",
                    type="ingress_exposes_service",
                )
            ],
        )
    )

    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1
    assert graph.nodes["ingress:prod:web"]["is_entry_point"] is True
    assert graph.nodes["service:prod:web"]["is_entry_point"] is True


@pytest.mark.asyncio
async def test_build_from_unified_result_supports_aws_only_graph():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[
                AWSGraphNode(
                    id="s3:123456789012:data-bucket",
                    type="s3_bucket",
                    namespace="123456789012",
                    metadata={"is_public": True},
                )
            ],
            edges=[],
        )
    )

    assert graph.number_of_nodes() == 1
    assert graph.number_of_edges() == 0
    assert graph.nodes["s3:123456789012:data-bucket"]["is_entry_point"] is True
    assert graph.nodes["s3:123456789012:data-bucket"]["is_crown_jewel"] is True


@pytest.mark.asyncio
async def test_build_from_unified_result_marks_ingress_exposed_pod_as_entry_point():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[
                K8sGraphNode(id="ingress:prod:web", type="ingress"),
                K8sGraphNode(id="service:prod:web", type="service"),
                K8sGraphNode(id="pod:prod:api", type="pod"),
            ],
            edges=[
                K8sGraphEdge(
                    source="ingress:prod:web",
                    target="service:prod:web",
                    type="ingress_exposes_service",
                ),
                K8sGraphEdge(
                    source="service:prod:web",
                    target="pod:prod:api",
                    type="service_targets_pod",
                ),
            ],
        )
    )

    assert graph.nodes["pod:prod:api"]["is_entry_point"] is True


@pytest.mark.asyncio
async def test_build_from_unified_result_marks_sensitive_targets_as_crown_jewels():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[
                K8sGraphNode(
                    id="secret:prod:db-creds",
                    type="secret",
                    metadata={"contains_db_credentials": True},
                ),
                AWSGraphNode(
                    id="rds:123456789012:prod-db",
                    type="rds",
                    namespace="123456789012",
                ),
                AWSGraphNode(
                    id="iam:123456789012:AdminRole",
                    type="iam_role",
                    namespace="123456789012",
                    metadata={"tier": 1},
                ),
            ],
            edges=[],
        )
    )

    assert graph.nodes["secret:prod:db-creds"]["is_crown_jewel"] is True
    assert graph.nodes["rds:123456789012:prod-db"]["is_crown_jewel"] is True
    assert graph.nodes["iam:123456789012:AdminRole"]["is_crown_jewel"] is True


@pytest.mark.asyncio
async def test_build_from_unified_result_supports_mixed_graph_and_preserves_cross_domain_edges():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[
                K8sGraphNode(id="pod:prod:api", type="pod"),
                AWSGraphNode(
                    id="iam:123456789012:AppRole",
                    type="iam_role",
                    namespace="123456789012",
                ),
            ],
            edges=[
                AWSGraphEdge(
                    source="pod:prod:api",
                    target="iam:123456789012:AppRole",
                    type="service_account_assumes_iam_role",
                )
            ],
        )
    )

    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1
    assert graph.has_edge("pod:prod:api", "iam:123456789012:AppRole")
    assert graph["pod:prod:api"]["iam:123456789012:AppRole"]["type"] == "service_account_assumes_iam_role"


@pytest.mark.asyncio
async def test_build_from_unified_result_adds_only_placeholder_nodes_for_dangling_edge_endpoints():
    graph = await GraphBuilder().build_from_unified_result(
        UnifiedGraphResult(
            nodes=[K8sGraphNode(id="pod:prod:api", type="pod")],
            edges=[
                AWSGraphEdge(
                    source="pod:prod:api",
                    target="iam:123456789012:MissingRole",
                    type="service_account_assumes_iam_role",
                )
            ],
        )
    )

    assert graph.number_of_nodes() == 2
    assert graph.has_edge("pod:prod:api", "iam:123456789012:MissingRole")
    assert graph.nodes["iam:123456789012:MissingRole"]["metadata"] == {"adapter_placeholder": True}
    assert graph.nodes["iam:123456789012:MissingRole"]["type"] == "iam_role"


@pytest.mark.asyncio
async def test_build_from_facts_remains_available_as_transitional_fallback():
    graph = await GraphBuilder().build_from_facts([
        Fact(
            fact_type=FactType.INGRESS_EXPOSES_SERVICE.value,
            subject_id="ingress:prod:web",
            subject_type=NodeType.INGRESS.value,
            object_id="service:prod:web",
            object_type=NodeType.SERVICE.value,
            metadata={"host": "app.example.com"},
        )
    ])

    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1
    assert graph.nodes["ingress:prod:web"]["is_entry_point"] is True
    assert graph["ingress:prod:web"]["service:prod:web"]["metadata"] == {"host": "app.example.com"}
