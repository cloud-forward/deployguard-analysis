"""Unit tests for Kubernetes RBAC fact parsing."""

from src.facts.extractors.k8s_rbac_parser import K8sRBACParser
from src.facts.types import FactType
from src.facts.validation.validation_gate import ValidationGate


def make_scan() -> dict:
    return {
        "pods": [
            {"namespace": "production", "name": "api-pod"},
            {"namespace": "production", "name": "worker-pod"},
        ],
        "service_accounts": [
            {"metadata": {"namespace": "production", "name": "api-sa"}},
            {"metadata": {"namespace": "production", "name": "job-sa"}},
        ],
        "secrets": [
            {"namespace": "production", "name": "db-creds"},
        ],
        "roles": [
            {
                "namespace": "production",
                "name": "secret-reader",
                "rules": [
                    {"resources": ["secrets"], "verbs": ["get"], "api_groups": [""]},
                    {"resources": ["configmaps"], "verbs": ["get"], "api_groups": [""]},
                    {"resources": ["pods/exec"], "verbs": ["create"], "api_groups": [""]},
                ],
            }
        ],
        "cluster_roles": [
            {
                "name": "pod-reader",
                "rules": [
                    {"resources": ["pods"], "verbs": ["list"], "api_groups": [""]},
                ],
            }
        ],
        "role_bindings": [
            {
                "name": "read-secrets",
                "namespace": "production",
                "role_ref_kind": "Role",
                "role_ref_name": "secret-reader",
                "subjects": [{"kind": "ServiceAccount", "name": "api-sa"}],
            },
            {
                "name": "use-cluster-role",
                "namespace": "production",
                "role_ref_kind": "ClusterRole",
                "role_ref_name": "pod-reader",
                "subjects": [{"kind": "ServiceAccount", "name": "job-sa"}],
            },
        ],
        "cluster_role_bindings": [
            {
                "name": "global-read",
                "role_ref_name": "pod-reader",
                "subjects": [{"kind": "ServiceAccount", "namespace": "production", "name": "api-sa"}],
            }
        ],
    }


def test_rbac_parser_outputs_schema_valid_binding_and_permission_facts():
    parser = K8sRBACParser()
    scan = make_scan()

    facts = parser.extract_bindings(scan) + parser.extract_permissions(scan)
    valid_facts, collection = ValidationGate().validate(facts, scan_id="scan-k8s-001")

    assert collection.error_count == 0
    assert len(valid_facts) == len(facts)
    assert any(f.fact_type == FactType.SERVICE_ACCOUNT_BOUND_ROLE.value for f in facts)
    assert any(f.fact_type == FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value for f in facts)
    assert any(f.fact_type == FactType.ROLE_GRANTS_RESOURCE.value for f in facts)
    assert any(f.fact_type == FactType.ROLE_GRANTS_POD_EXEC.value for f in facts)


def test_rbac_parser_skips_configmap_rule_emission_that_would_fail_validation():
    parser = K8sRBACParser()
    facts = parser.extract_permissions(make_scan())

    target_ids = {fact.object_id for fact in facts if fact.fact_type == FactType.ROLE_GRANTS_RESOURCE.value}

    assert "configmap:production:anything" not in target_ids
    assert all("configmap" not in fact.object_type for fact in facts)
