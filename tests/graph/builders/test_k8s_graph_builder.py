"""Contract tests for the Kubernetes graph builder."""

from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.graph.builders.k8s_graph_builder import K8sGraphBuilder


def make_k8s_scan() -> dict:
    """Return a small Kubernetes scan fixture with core internal resources."""
    return {
        "scan_id": "scan-k8s-001",
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
                        "volume_mounts": [],
                        "env_from_secrets": [],
                    }
                ],
            }
        ],
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/WebAppRole"},
                }
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
                "rules": [{"resources": ["pods"], "verbs": ["*"], "api_groups": [""]}],
            }
        ],
        "secrets": [
            {
                "namespace": "production",
                "name": "db-creds",
                "type": "Opaque",
            }
        ],
        "services": [
            {
                "namespace": "production",
                "name": "api-service",
                "selector": {"app": "api"},
                "port": 8080,
                "type": "ClusterIP",
            }
        ],
        "ingresses": [
            {
                "namespace": "production",
                "name": "api-ingress",
                "rules": [
                    {
                        "host": "api.example.com",
                        "paths": [
                            {
                                "path": "/",
                                "backend_service": "api-service",
                                "backend_port": 8080,
                            }
                        ],
                    }
                ],
            }
        ],
    }


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
            metadata={"host": "api.example.com", "path": "/", "backend_port": 8080},
        ),
    ]


def build(facts: list[Fact], k8s_scan: dict, scan_id: str = "scan-k8s-001"):
    """Build graph from facts and raw scan data."""
    builder = K8sGraphBuilder()
    return builder.build(facts=facts, k8s_scan=k8s_scan, scan_id=scan_id)


def test_build_exists_and_returns_lists():
    nodes, edges = build(make_internal_facts(), make_k8s_scan())

    assert isinstance(nodes, list)
    assert isinstance(edges, list)


def test_nodes_are_created_from_raw_k8s_scan_not_only_fact_endpoints():
    nodes, _ = build(
        facts=[
            Fact(
                fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
                subject_id="pod:production:api-pod",
                subject_type=NodeType.POD.value,
                object_id="sa:production:api-sa",
                object_type=NodeType.SERVICE_ACCOUNT.value,
                metadata={},
            )
        ],
        k8s_scan=make_k8s_scan(),
    )

    node_ids = {node.id for node in nodes}

    assert "pod:production:api-pod" in node_ids
    assert "sa:production:api-sa" in node_ids
    assert "role:production:secret-reader" in node_ids
    assert "cluster_role:cluster-admin" in node_ids
    assert "secret:production:db-creds" in node_ids
    assert "service:production:api-service" in node_ids
    assert "ingress:production:api-ingress" in node_ids


def test_edges_are_created_from_valid_kubernetes_facts():
    _, edges = build(make_internal_facts(), make_k8s_scan())

    edge_triplets = {(edge.source, edge.target, edge.type) for edge in edges}

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


def test_only_kubernetes_internal_nodes_and_edges_are_returned():
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

    nodes, edges = build(facts, make_k8s_scan())

    node_ids = {node.id for node in nodes}
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in edges}

    assert "iam:123456789012:WebAppRole" not in node_ids
    assert "rds:123456789012:production-db" not in node_ids
    assert (
        "sa:production:api-sa",
        "iam:123456789012:WebAppRole",
        FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
    ) not in edge_triplets
    assert (
        "secret:production:db-creds",
        "rds:123456789012:production-db",
        FactType.SECRET_CONTAINS_CREDENTIALS.value,
    ) not in edge_triplets


def test_cross_domain_edges_are_excluded_even_when_present_in_fact_input():
    _, edges = build(
        facts=[
            Fact(
                fact_type=FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
                subject_id="sa:production:api-sa",
                subject_type=NodeType.SERVICE_ACCOUNT.value,
                object_id="iam:123456789012:WebAppRole",
                object_type=NodeType.IAM_ROLE.value,
                metadata={"via": "irsa"},
            )
        ],
        k8s_scan=make_k8s_scan(),
    )

    assert edges == []


def test_node_metadata_is_enriched_from_raw_k8s_scan():
    nodes, _ = build(make_internal_facts(), make_k8s_scan())
    nodes_by_id = {node.id: node for node in nodes}

    pod = nodes_by_id["pod:production:api-pod"]
    assert pod.metadata["service_account"] == "api-sa"
    assert pod.metadata["node_name"] == "worker-1"
    assert pod.metadata["labels"] == {"app": "api"}
    assert pod.metadata["container_images"] == ["nginx:1.25"]

    service_account = nodes_by_id["sa:production:api-sa"]
    assert service_account.metadata["annotations"]["eks.amazonaws.com/role-arn"].endswith(":role/WebAppRole")

    role = nodes_by_id["role:production:secret-reader"]
    assert role.metadata["rules"] == [{"resources": ["secrets"], "verbs": ["get"], "api_groups": [""]}]

    cluster_role = nodes_by_id["cluster_role:cluster-admin"]
    assert cluster_role.metadata["rules"] == [{"resources": ["pods"], "verbs": ["*"], "api_groups": [""]}]

    secret = nodes_by_id["secret:production:db-creds"]
    assert secret.metadata["secret_type"] == "Opaque"

    service = nodes_by_id["service:production:api-service"]
    assert service.metadata["selector"] == {"app": "api"}
    assert service.metadata["port"] == 8080
    assert service.metadata["service_type"] == "ClusterIP"

    ingress = nodes_by_id["ingress:production:api-ingress"]
    assert ingress.metadata["rules"][0]["host"] == "api.example.com"


def test_missing_internal_nodes_referenced_by_facts_are_created_as_fallback():
    nodes, edges = build(
        facts=[
            Fact(
                fact_type=FactType.SERVICE_TARGETS_POD.value,
                subject_id="service:production:missing-service",
                subject_type=NodeType.SERVICE.value,
                object_id="pod:production:missing-pod",
                object_type=NodeType.POD.value,
                metadata={"port": 8080},
            )
        ],
        k8s_scan=make_k8s_scan(),
    )

    nodes_by_id = {node.id: node for node in nodes}
    edge_triplets = {(edge.source, edge.target, edge.type) for edge in edges}

    assert "service:production:missing-service" in nodes_by_id
    assert "pod:production:missing-pod" in nodes_by_id
    assert nodes_by_id["service:production:missing-service"].metadata["discovered_from"] == "fact_fallback"
    assert nodes_by_id["pod:production:missing-pod"].metadata["discovered_from"] == "fact_fallback"
    assert (
        "service:production:missing-service",
        "pod:production:missing-pod",
        FactType.SERVICE_TARGETS_POD.value,
    ) in edge_triplets


def test_duplicate_k8s_facts_do_not_create_duplicate_edges():
    fact = Fact(
        fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
        subject_id="pod:production:api-pod",
        subject_type=NodeType.POD.value,
        object_id="sa:production:api-sa",
        object_type=NodeType.SERVICE_ACCOUNT.value,
        metadata={},
    )

    _, edges = build([fact, fact], make_k8s_scan())

    matching_edges = [
        edge for edge in edges
        if edge.source == "pod:production:api-pod"
        and edge.target == "sa:production:api-sa"
        and edge.type == FactType.POD_USES_SERVICE_ACCOUNT.value
    ]

    assert len(matching_edges) == 1
