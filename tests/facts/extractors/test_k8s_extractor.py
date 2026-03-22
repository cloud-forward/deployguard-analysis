from src.facts.extractors.k8s_extractor import K8sFactExtractor
from src.facts.validation.validators import FactValidator
from src.facts.types import FactType, NodeType


def test_extract_role_grants_resource_reads_nested_secret_metadata():
    extractor = K8sFactExtractor()
    scan = {
        "scan_id": "scan-k8s-001",
        "roles": [
            {
                "namespace": "production",
                "name": "secret-reader",
                "rules": [
                    {
                        "resources": ["secrets"],
                        "verbs": ["get"],
                        "api_groups": [""],
                    }
                ],
            }
        ],
        "cluster_roles": [],
        "secrets": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "db-creds",
                },
                "type": "Opaque",
            }
        ],
        "pods": [],
        "services": [],
        "ingresses": [],
        "service_accounts": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "network_policies": [],
    }

    facts = extractor.extract(scan)

    assert (
        FactType.ROLE_GRANTS_RESOURCE.value,
        "role:production:secret-reader",
        NodeType.ROLE.value,
        "secret:production:db-creds",
        NodeType.SECRET.value,
    ) in {
        (
            fact.fact_type,
            fact.subject_id,
            fact.subject_type,
            fact.object_id,
            fact.object_type,
        )
        for fact in facts
    }


def test_extract_role_grants_resource_emits_service_account_target_for_named_resource():
    extractor = K8sFactExtractor()
    validator = FactValidator()
    scan = {
        "scan_id": "scan-k8s-001",
        "roles": [
            {
                "namespace": "production",
                "name": "sa-reader",
                "rules": [
                    {
                        "resources": ["serviceaccounts"],
                        "verbs": ["get"],
                        "api_groups": [""],
                        "resource_names": ["api-sa"],
                    }
                ],
            }
        ],
        "cluster_roles": [],
        "secrets": [],
        "pods": [],
        "services": [],
        "ingresses": [],
        "service_accounts": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "network_policies": [],
    }

    facts = extractor.extract(scan)

    sa_fact = next(
        fact
        for fact in facts
        if fact.fact_type == FactType.ROLE_GRANTS_RESOURCE.value
        and fact.object_type == NodeType.SERVICE_ACCOUNT.value
    )

    assert sa_fact.subject_id == "role:production:sa-reader"
    assert sa_fact.object_id == "sa:production:api-sa"
    assert validator.validate(sa_fact) == []


def test_extract_role_grants_resource_ignores_unsupported_configmap_rules():
    extractor = K8sFactExtractor()
    scan = {
        "scan_id": "scan-k8s-001",
        "roles": [
            {
                "namespace": "production",
                "name": "configmap-reader",
                "rules": [
                    {
                        "resources": ["configmaps"],
                        "verbs": ["get"],
                        "api_groups": [""],
                        "resource_names": ["app-config"],
                    }
                ],
            }
        ],
        "cluster_roles": [],
        "secrets": [],
        "pods": [],
        "services": [],
        "ingresses": [],
        "service_accounts": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "network_policies": [],
    }

    facts = extractor.extract(scan)

    assert [
        fact for fact in facts
        if fact.fact_type == FactType.ROLE_GRANTS_RESOURCE.value
    ] == []


def test_extract_escape_path_emits_node_credential_for_kubelet_cert():
    extractor = K8sFactExtractor()
    scan = {
        "scan_id": "scan-k8s-001",
        "roles": [],
        "cluster_roles": [
            {
                "name": "cluster-admin",
                "rules": [{"resources": ["pods"], "verbs": ["*"], "api_groups": ["*"]}],
            }
        ],
        "secrets": [],
        "pods": [
            {
                "namespace": "production",
                "name": "escape-pod",
                "node_name": "worker-1",
                "service_account": "admin-sa",
                "containers": [
                    {
                        "name": "escape",
                        "security_context": {"privileged": True},
                        "volume_mounts": [],
                    }
                ],
                "volume_mounts": [],
                "env_from_secrets": [],
                "labels": {},
            }
        ],
        "services": [],
        "ingresses": [],
        "service_accounts": [],
        "role_bindings": [],
        "cluster_role_bindings": [
            {
                "subjects": [{"kind": "ServiceAccount", "name": "admin-sa", "namespace": "production"}],
                "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
            }
        ],
        "network_policies": [],
    }

    facts = extractor.extract(scan)

    assert (
        FactType.EXPOSES_TOKEN.value,
        "node:worker-1",
        NodeType.NODE.value,
        "node_cred:worker-1:kubelet_cert",
        NodeType.NODE_CREDENTIAL.value,
    ) in {
        (
            fact.fact_type,
            fact.subject_id,
            fact.subject_type,
            fact.object_id,
            fact.object_type,
        )
        for fact in facts
    }
