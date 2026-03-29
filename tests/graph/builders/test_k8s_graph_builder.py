"""Contract tests for the Kubernetes graph builder."""

from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.graph.builders.build_result_types import K8sBuildResult, unpack_build_result
from src.graph.builders.k8s_graph_builder import K8sGraphBuilder


def make_k8s_scan() -> dict:
    """Return a small Kubernetes scan fixture with core internal resources."""
    return {
        "scan_id": "scan-k8s-001",
        "cluster_id": "cluster-001",
        "pods": [
            {
                "namespace": "production",
                "name": "api-pod",
                "service_account": "api-sa",
                "node_name": "worker-1",
                "labels": {"app": "api"},
                "containers": [
                    {
                        "name": "api",
                        "image": "nginx:1.25",
                        "security_context": {"privileged": False},
                    }
                ],
                "volume_mounts": [],
                "env_from_secrets": [],
            }
        ],
        "service_accounts": [
            {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/WebAppRole",
                },
            }
        ],
        "roles": [
            {
                "namespace": "production",
                "name": "secret-reader",
                "rules": [{"resources": ["secrets"], "verbs": ["get"], "api_groups": [""]}],
            }
        ],
        "cluster_roles": [
            {
                "name": "cluster-admin",
                "rules": [{"resources": ["pods"], "verbs": ["*"], "api_groups": ["*"]}],
            }
        ],
        "secrets": [
            {
                "namespace": "production",
                "name": "db-creds",
                "type": "Opaque",
                "data": {"username": "dXNlcg=="},
                "stringData": {"password": "plaintext"},
            }
        ],
        "services": [
            {
                "namespace": "production",
                "name": "api-service",
                "type": "ClusterIP",
                "selector": {"app": "api"},
                "port": 80,
                "ports": [{"port": 80, "targetPort": 8080}],
            }
        ],
        "ingresses": [
            {
                "namespace": "production",
                "name": "api-ingress",
                "ingress_class_name": "nginx",
                "rules": [
                    {
                        "host": "api.example.com",
                        "paths": [
                            {
                                "path": "/",
                                "backend_service": "api-service",
                                "backend_port": 80,
                            }
                        ],
                    }
                ],
            }
        ],
    }


def build(builder: K8sGraphBuilder, facts: list[Fact], k8s_scan: dict) -> K8sBuildResult:
    return builder.build(facts, k8s_scan, scan_id="scan-k8s-001")


def make_internal_facts() -> list[Fact]:
    """Return a minimal set of valid Kubernetes-internal facts."""
    return [
        Fact(
            fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
            subject_id="pod:production:api-pod",
            subject_type=NodeType.POD.value,
            object_id="sa:production:api-sa",
            object_type=NodeType.SERVICE_ACCOUNT.value,
            metadata={},
        ),
        Fact(
            fact_type=FactType.INGRESS_EXPOSES_SERVICE.value,
            subject_id="ingress:production:api-ingress",
            subject_type=NodeType.INGRESS.value,
            object_id="service:production:api-service",
            object_type=NodeType.SERVICE.value,
            metadata={},
        ),
    ]


def test_build_returns_k8s_build_result():
    builder = K8sGraphBuilder()

    result = build(builder, make_internal_facts(), make_k8s_scan())

    assert isinstance(result, K8sBuildResult)
    assert result.metadata == {
        "graph_id": "scan-k8s-001-graph",
        "scan_id": "scan-k8s-001",
        "cluster_id": "cluster-001",
    }


def test_build_accepts_explicit_scan_id_and_uses_it_in_metadata():
    builder = K8sGraphBuilder()

    result = builder.build(make_internal_facts(), make_k8s_scan(), scan_id="explicit-k8s-scan")

    assert result.metadata["scan_id"] == "explicit-k8s-scan"
    assert result.metadata["graph_id"] == "explicit-k8s-scan-graph"


def test_nodes_are_created_from_raw_k8s_scan_not_only_fact_endpoints():
    builder = K8sGraphBuilder()

    result = build(builder, make_internal_facts(), make_k8s_scan())
    node_ids = {node.id for node in result.nodes}

    assert "pod:production:api-pod" in node_ids
    assert "sa:production:api-sa" in node_ids
    assert "role:production:secret-reader" in node_ids
    assert "cluster_role:cluster-admin" in node_ids
    assert "secret:production:db-creds" in node_ids
    assert "service:production:api-service" in node_ids
    assert "ingress:production:api-ingress" in node_ids
    assert "node:worker-1" in node_ids
    assert "container_image:nginx:1.25" in node_ids


def test_edges_are_created_from_valid_kubernetes_facts():
    builder = K8sGraphBuilder()

    result = build(builder, make_internal_facts(), make_k8s_scan())
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in result.edges}

    assert (
        "pod:production:api-pod",
        "sa:production:api-sa",
        FactType.POD_USES_SERVICE_ACCOUNT.value,
    ) in edge_triplets
    assert (
        "ingress:production:api-ingress",
        "service:production:api-service",
        FactType.INGRESS_EXPOSES_SERVICE.value,
    ) in edge_triplets


def test_cross_domain_edges_are_excluded_even_when_present_in_fact_input():
    builder = K8sGraphBuilder()
    facts = make_internal_facts() + [
        Fact(
            fact_type=FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
            subject_id="sa:production:api-sa",
            subject_type=NodeType.SERVICE_ACCOUNT.value,
            object_id="iam:123456789012:WebAppRole",
            object_type=NodeType.IAM_ROLE.value,
            metadata={"via": "irsa"},
        ),
        Fact(
            fact_type=FactType.SECRET_CONTAINS_CREDENTIALS.value,
            subject_id="secret:production:db-creds",
            subject_type=NodeType.SECRET.value,
            object_id="rds:123456789012:production-db",
            object_type=NodeType.RDS.value,
            metadata={"confidence": "high"},
        ),
    ]

    result = build(builder, facts, make_k8s_scan())
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in result.edges}
    node_ids = {node.id for node in result.nodes}

    assert ("sa:production:api-sa", "iam:123456789012:WebAppRole", FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value) not in edge_triplets
    assert ("secret:production:db-creds", "rds:123456789012:production-db", FactType.SECRET_CONTAINS_CREDENTIALS.value) not in edge_triplets
    assert "iam:123456789012:WebAppRole" not in node_ids
    assert "rds:123456789012:production-db" not in node_ids


def test_node_metadata_is_enriched_from_raw_k8s_scan():
    builder = K8sGraphBuilder()

    result = build(builder, make_internal_facts(), make_k8s_scan())
    nodes_by_id = {node.id: node for node in result.nodes}

    assert nodes_by_id["pod:production:api-pod"].metadata["container_images"] == ["nginx:1.25"]
    assert nodes_by_id["sa:production:api-sa"].metadata["annotations"]["eks.amazonaws.com/role-arn"].endswith(":role/WebAppRole")
    assert nodes_by_id["secret:production:db-creds"].metadata["secret_type"] == "Opaque"
    assert nodes_by_id["service:production:api-service"].metadata["service_type"] == "ClusterIP"


def test_secret_node_metadata_preserves_precomputed_key_lists():
    builder = K8sGraphBuilder()
    k8s_scan = make_k8s_scan()
    k8s_scan["secrets"] = [
        {
            "namespace": "production",
            "name": "db-creds",
            "type": "Opaque",
            "data_keys": ["database", "host", "username"],
            "string_data_keys": ["password", "port"],
        }
    ]

    result = build(builder, make_internal_facts(), k8s_scan)
    nodes_by_id = {node.id: node for node in result.nodes}

    assert nodes_by_id["secret:production:db-creds"].metadata["data_keys"] == [
        "database",
        "host",
        "username",
    ]
    assert nodes_by_id["secret:production:db-creds"].metadata["string_data_keys"] == [
        "password",
        "port",
    ]


def test_missing_internal_nodes_referenced_by_facts_are_created_as_fallback():
    builder = K8sGraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.SERVICE_TARGETS_POD.value,
            subject_id="service:production:missing-service",
            subject_type=NodeType.SERVICE.value,
            object_id="pod:production:missing-pod",
            object_type=NodeType.POD.value,
            metadata={"selector": {"app": "missing"}},
        )
    ]

    result = builder.build(
        facts,
        {"scan_id": "scan-k8s-001", "cluster_id": "cluster-001"},
        scan_id="scan-k8s-001",
    )
    nodes_by_id = {node.id: node for node in result.nodes}
    matching_edges = [
        edge for edge in result.edges
        if edge.source == "service:production:missing-service"
        and edge.target == "pod:production:missing-pod"
    ]

    assert nodes_by_id["service:production:missing-service"].metadata["discovered_from"] == "fact_fallback"
    assert nodes_by_id["pod:production:missing-pod"].metadata["discovered_from"] == "fact_fallback"
    assert len(matching_edges) == 1
    assert matching_edges[0].metadata == {"selector": {"app": "missing"}}


def test_duplicate_k8s_facts_do_not_create_duplicate_edges():
    builder = K8sGraphBuilder()
    duplicated_fact = Fact(
        fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
        subject_id="pod:production:api-pod",
        subject_type=NodeType.POD.value,
        object_id="sa:production:api-sa",
        object_type=NodeType.SERVICE_ACCOUNT.value,
        metadata={},
    )

    result = build(builder, [duplicated_fact, duplicated_fact], make_k8s_scan())
    matching_edges = [
        edge for edge in result.edges
        if edge.source == "pod:production:api-pod"
        and edge.target == "sa:production:api-sa"
        and edge.type == FactType.POD_USES_SERVICE_ACCOUNT.value
    ]

    assert len(matching_edges) == 1


def test_transitional_unpack_adapter_preserves_node_and_edge_payloads():
    builder = K8sGraphBuilder()
    result = build(builder, make_internal_facts(), make_k8s_scan())

    nodes, edges = unpack_build_result(result)

    assert nodes == result.nodes
    assert edges == result.edges
