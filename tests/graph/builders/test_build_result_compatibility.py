"""Tests for explicit typed-graph compatibility helpers."""

from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import (
    graph_edge_attrs,
    graph_edge_identity,
    graph_node_attrs,
    graph_node_identity,
)
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


def test_graph_node_attrs_normalizes_k8s_and_aws_nodes_to_common_shape():
    k8s_node = K8sGraphNode(
        id="pod:prod:api",
        type="pod",
        is_entry_point=True,
        is_crown_jewel=False,
        base_risk=0.3,
        metadata={"namespace": "prod"},
    )
    aws_node = AWSGraphNode(
        id="iam:123456789012:AppRole",
        type="iam_role",
        namespace="123456789012",
        metadata={"tier": 1},
    )

    assert graph_node_attrs(k8s_node) == {
        "id": "pod:prod:api",
        "type": "pod",
        "is_entry_point": True,
        "is_crown_jewel": False,
        "base_risk": 0.3,
        "metadata": {"namespace": "prod"},
    }
    assert graph_node_attrs(aws_node) == {
        "id": "iam:123456789012:AppRole",
        "type": "iam_role",
        "is_entry_point": False,
        "is_crown_jewel": False,
        "base_risk": 0.0,
        "metadata": {"tier": 1},
    }


def test_graph_identity_helpers_match_merge_contract():
    k8s_node = K8sGraphNode(id="pod:prod:api", type="pod")
    aws_edge = AWSGraphEdge(
        source="sa:prod:api",
        target="iam:123456789012:AppRole",
        type="service_account_assumes_iam_role",
        metadata={"bridge_source": "irsa"},
    )
    k8s_edge = K8sGraphEdge(
        source="pod:prod:api",
        target="sa:prod:api",
        type="pod_uses_service_account",
    )

    assert graph_node_identity(k8s_node) == "pod:prod:api"
    assert graph_edge_identity(aws_edge) == (
        "sa:prod:api",
        "iam:123456789012:AppRole",
        "service_account_assumes_iam_role",
    )
    assert graph_edge_attrs(k8s_edge) == {
        "source": "pod:prod:api",
        "target": "sa:prod:api",
        "type": "pod_uses_service_account",
        "metadata": {},
    }
