from src.facts.extractors.lateral_move_extractor import LateralMoveExtractor
from src.facts.types import FactType


def make_scan(network_policies):
    return {
        "scan_id": "scan-k8s-001",
        "pods": [
            {"namespace": "frontend", "name": "web"},
            {"namespace": "backend", "name": "api"},
        ],
        "services": [
            {"namespace": "backend", "name": "db-service", "port": 5432},
            {"namespace": "ops", "name": "admin-api", "port": 8443},
        ],
        "network_policies": network_policies,
    }


def lateral_pairs(facts):
    return {
        (fact.subject_id, fact.object_id, fact.metadata["cross_namespace"])
        for fact in facts
        if fact.fact_type == FactType.LATERAL_MOVE.value
    }


def test_no_network_policies_allows_lateral_move_facts():
    extractor = LateralMoveExtractor()

    facts = extractor.extract(make_scan(network_policies=[]))

    assert lateral_pairs(facts) == {
        ("pod:frontend:web", "service:backend:db-service", True),
        ("pod:frontend:web", "service:ops:admin-api", True),
        ("pod:backend:api", "service:backend:db-service", False),
        ("pod:backend:api", "service:ops:admin-api", True),
    }


def test_network_policy_in_one_namespace_does_not_suppress_unrelated_namespaces():
    extractor = LateralMoveExtractor()

    facts = extractor.extract(
        make_scan(network_policies=[{"namespace": "backend", "name": "deny-all"}])
    )

    assert lateral_pairs(facts) == {
        ("pod:frontend:web", "service:ops:admin-api", True),
    }


def test_network_policy_suppression_applies_only_to_covered_namespace_scope():
    extractor = LateralMoveExtractor()

    facts = extractor.extract(
        make_scan(
            network_policies=[
                {"metadata": {"namespace": "ops", "name": "ops-deny-all"}}
            ]
        )
    )

    assert lateral_pairs(facts) == {
        ("pod:frontend:web", "service:backend:db-service", True),
        ("pod:backend:api", "service:backend:db-service", False),
    }


def test_same_workload_service_target_is_not_emitted_as_lateral_move():
    extractor = LateralMoveExtractor()
    scan = {
        "scan_id": "scan-k8s-001",
        "pods": [
            {"namespace": "backend", "name": "api", "labels": {"app": "api"}},
            {"namespace": "frontend", "name": "web", "labels": {"app": "web"}},
        ],
        "services": [
            {
                "namespace": "backend",
                "name": "api-admin",
                "port": 8443,
                "selector": {"app": "api"},
            },
            {
                "namespace": "backend",
                "name": "db-service",
                "port": 5432,
                "selector": {"app": "db"},
            },
        ],
        "network_policies": [],
    }

    facts = extractor.extract(scan)

    assert lateral_pairs(facts) == {
        ("pod:frontend:web", "service:backend:api-admin", True),
        ("pod:frontend:web", "service:backend:db-service", True),
        ("pod:backend:api", "service:backend:db-service", False),
    }
