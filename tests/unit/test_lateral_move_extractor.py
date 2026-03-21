"""Unit tests for bounded lateral move fact extraction."""

from src.facts.extractors.lateral_move_extractor import LateralMoveExtractor
from src.facts.types import FactType
from src.facts.validation.validation_gate import ValidationGate


def make_scan() -> dict:
    return {
        "scan_id": "scan-k8s-001",
        "pods": [
            {"namespace": "production", "name": "api-pod"},
            {"namespace": "monitoring", "name": "metrics-pod"},
        ],
        "services": [
            {"namespace": "data", "name": "postgres-db", "port": 5432},
        ],
        "network_policies": [],
    }


def test_lateral_move_output_is_schema_valid():
    extractor = LateralMoveExtractor()
    facts = extractor.extract(make_scan())
    valid_facts, collection = ValidationGate().validate(facts, scan_id="scan-k8s-001")

    assert collection.error_count == 0
    assert len(valid_facts) == len(facts)
    assert all(fact.fact_type == FactType.LATERAL_MOVE.value for fact in facts)


def test_unrelated_network_policy_does_not_suppress_all_lateral_move_results():
    extractor = LateralMoveExtractor()
    scan = make_scan()
    scan["network_policies"] = [
        {"namespace": "unrelated", "name": "default-deny"},
    ]

    facts = extractor.extract(scan)
    fact_pairs = {(fact.subject_id, fact.object_id) for fact in facts}

    assert ("pod:production:api-pod", "service:data:postgres-db") in fact_pairs
    assert ("pod:monitoring:metrics-pod", "service:data:postgres-db") in fact_pairs


def test_lateral_move_is_suppressed_only_for_pods_in_protected_namespace():
    extractor = LateralMoveExtractor()
    scan = make_scan()
    scan["network_policies"] = [
        {"namespace": "monitoring", "name": "default-deny"},
    ]

    facts = extractor.extract(scan)
    fact_pairs = {(fact.subject_id, fact.object_id) for fact in facts}

    assert ("pod:production:api-pod", "service:data:postgres-db") in fact_pairs
    assert ("pod:monitoring:metrics-pod", "service:data:postgres-db") not in fact_pairs
