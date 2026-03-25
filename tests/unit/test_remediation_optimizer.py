import networkx as nx

from app.core.remediation_optimizer import RemediationCandidate, RemediationOptimizer


def test_optimizer_prefers_shared_low_cost_edge_fix_that_blocks_multiple_paths():
    graph = nx.DiGraph()
    graph.add_node("ingress:prod:web", type="ingress")
    graph.add_node("service:prod:web", type="service")
    graph.add_node("pod:prod:api", type="pod")
    graph.add_node("iam:123:AppRole", type="iam_role")
    graph.add_node("s3:123:data", type="s3_bucket")

    enriched_paths = [
        {
            "path_id": "path-a",
            "path": ["ingress:prod:web", "service:prod:web", "pod:prod:api"],
            "raw_final_risk": 0.9,
            "risk_score": 0.9,
            "length": 3,
            "edges": [
                {"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"},
                {"source": "service:prod:web", "target": "pod:prod:api", "type": "service_targets_pod"},
            ],
        },
        {
            "path_id": "path-b",
            "path": ["ingress:prod:web", "service:prod:web", "iam:123:AppRole", "s3:123:data"],
            "raw_final_risk": 0.6,
            "risk_score": 0.6,
            "length": 4,
            "edges": [
                {"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"},
                {"source": "iam:123:AppRole", "target": "s3:123:data", "type": "iam_role_access_resource"},
            ],
        },
    ]

    result = RemediationOptimizer().optimize(enriched_paths, graph)

    assert result["summary"]["total_paths"] == 2
    assert result["summary"]["blocked_paths"] == 2
    assert result["recommendations"][0]["edge_source"] == "ingress:prod:web"
    assert result["recommendations"][0]["edge_target"] == "service:prod:web"
    assert result["recommendations"][0]["edge_type"] == "ingress_exposes_service"
    assert result["recommendations"][0]["fix_type"] == "restrict_ingress"
    assert result["recommendations"][0]["blocked_path_ids"] == ["path-a", "path-b"]
    assert result["recommendations"][0]["covered_risk"] == 1.5
    assert result["recommendations"][0]["cumulative_risk_reduction"] == 1.0
    assert result["recommendations"][0]["fix_cost"] == 3.2
    assert result["recommendations"][0]["fix_description"] == (
        "Change ingress `ingress:prod:web` -> service `service:prod:web`: restrict ingress exposure. "
        "This matters because this public ingress step exposes an internal service. "
        "Expected effect: block 2 risky paths and reduce raw risk by 1.50 (cumulative reduction ratio 1.00)."
    )


def test_optimizer_uses_fix_type_cost_and_selects_multiple_edge_breakpoints_when_needed():
    graph = nx.DiGraph()
    graph.add_node("node:worker-1", type="node")
    graph.add_node("pod:prod:escape", type="pod")
    graph.add_node("service:prod:web", type="service")
    graph.add_node("ingress:prod:web", type="ingress")
    graph.add_node("s3:123:data", type="s3_bucket")
    graph.add_node("iam:123:BatchRole", type="iam_role")

    enriched_paths = [
        {
            "path_id": "path-ingress",
            "path": ["ingress:prod:web", "service:prod:web", "s3:123:data"],
            "raw_final_risk": 0.8,
            "risk_score": 0.8,
            "length": 2,
            "edges": [
                {"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"},
            ],
        },
        {
            "path_id": "path-escape",
            "path": ["pod:prod:escape", "node:worker-1", "iam:123:BatchRole"],
            "raw_final_risk": 0.7,
            "risk_score": 0.7,
            "length": 2,
            "edges": [
                {"source": "pod:prod:escape", "target": "node:worker-1", "type": "escapes_to"},
                {"source": "node:worker-1", "target": "iam:123:BatchRole", "type": "unknown"},
            ],
        },
    ]

    result = RemediationOptimizer().optimize(enriched_paths, graph)

    recommendation_ids = [item["id"] for item in result["recommendations"]]

    assert result["summary"]["selected_count"] == 2
    assert result["recommendations"][0]["fix_type"] == "restrict_ingress"
    assert result["recommendations"][1]["fix_type"] == "remove_privileged"
    assert result["recommendations"][0]["fix_cost"] == 3.2
    assert result["recommendations"][1]["fix_cost"] == 3.0
    assert result["recommendations"][0]["covered_risk"] == 0.8
    assert result["recommendations"][0]["cumulative_risk_reduction"] == 0.533333
    assert result["recommendations"][1]["covered_risk"] == 0.7
    assert result["recommendations"][1]["cumulative_risk_reduction"] == 1.0
    assert any(item.startswith("restrict_ingress:") for item in recommendation_ids)
    assert any(item.startswith("remove_privileged:") for item in recommendation_ids)
    assert result["recommendations"][1]["fix_description"] == (
        "Change pod `pod:prod:escape` -> node `node:worker-1`: remove privileged or escape-capable pod settings. "
        "This matters because this edge represents a container escape step to the node. "
        "Expected effect: block 1 risky path and reduce raw risk by 0.70 (cumulative reduction ratio 1.00)."
    )


def test_optimizer_uses_higher_effective_cost_for_cluster_role_bindings_than_role_bindings():
    graph = nx.DiGraph()
    graph.add_node("sa:prod:api", type="service_account")
    graph.add_node("role:prod:reader", type="role")
    graph.add_node("cluster_role:admin", type="cluster_role")
    graph.add_node("secret:prod:db", type="secret")

    enriched_paths = [
        {
            "path_id": "path-role",
            "path": ["sa:prod:api", "role:prod:reader", "secret:prod:db"],
            "raw_final_risk": 0.6,
            "edges": [
                {"source": "sa:prod:api", "target": "role:prod:reader", "type": "service_account_bound_role"},
            ],
        },
        {
            "path_id": "path-cluster-role",
            "path": ["sa:prod:api", "cluster_role:admin", "secret:prod:db"],
            "raw_final_risk": 0.6,
            "edges": [
                {"source": "sa:prod:api", "target": "cluster_role:admin", "type": "service_account_bound_cluster_role"},
            ],
        },
    ]

    result = RemediationOptimizer().optimize(enriched_paths, graph)

    costs_by_edge_type = {item["edge_type"]: item["fix_cost"] for item in result["recommendations"]}
    assert costs_by_edge_type["service_account_bound_role"] == 1.8
    assert costs_by_edge_type["service_account_bound_cluster_role"] == 2.8


def test_normalize_paths_skips_invalid_path_shape_missing_edges_and_invalid_risk_values():
    optimizer = RemediationOptimizer()

    normalized = optimizer._normalize_paths(
        [
            {
                "path_id": "too-short",
                "path": ["pod:prod:api"],
                "raw_final_risk": 0.9,
                "edges": [{"source": "a", "target": "b", "type": "ingress_exposes_service"}],
            },
            {
                "path_id": "missing-edges",
                "path": ["a", "b"],
                "raw_final_risk": 0.9,
                "edges": [],
            },
            {
                "path_id": "non-numeric-risk",
                "path": ["a", "b"],
                "raw_final_risk": "high",
                "edges": [{"source": "a", "target": "b", "type": "ingress_exposes_service"}],
            },
            {
                "path_id": "zero-risk",
                "path": ["a", "b"],
                "raw_final_risk": 0.0,
                "edges": [{"source": "a", "target": "b", "type": "ingress_exposes_service"}],
            },
            {
                "path_id": "negative-risk",
                "path": ["a", "b"],
                "raw_final_risk": -0.1,
                "edges": [{"source": "a", "target": "b", "type": "ingress_exposes_service"}],
            },
            {
                "path_id": "valid",
                "path": ["ingress:prod:web", "service:prod:web"],
                "raw_final_risk": 0.7,
                "edges": [{"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"}],
            },
        ]
    )

    assert normalized == [
        {
            "path_index": 5,
            "path_id": "valid",
            "path": ["ingress:prod:web", "service:prod:web"],
            "raw_final_risk": 0.7,
            "edges": [{"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"}],
        }
    ]


def test_build_candidates_skips_unsupported_edge_types():
    optimizer = RemediationOptimizer()
    graph = nx.DiGraph()
    graph.add_node("ingress:prod:web", type="ingress")
    graph.add_node("service:prod:web", type="service")
    graph.add_node("pod:prod:api", type="pod")

    risky_paths = optimizer._normalize_paths(
        [
            {
                "path_id": "path-a",
                "path": ["ingress:prod:web", "service:prod:web", "pod:prod:api"],
                "raw_final_risk": 0.9,
                "edges": [
                    {"source": "ingress:prod:web", "target": "service:prod:web", "type": "ingress_exposes_service"},
                    {"source": "service:prod:web", "target": "pod:prod:api", "type": "unsupported_edge_type"},
                ],
            }
        ]
    )

    candidates = optimizer._build_candidates(risky_paths, graph)

    assert list(candidates) == ["restrict_ingress:ingress:prod:web:service:prod:web:ingress_exposes_service"]
    assert candidates["restrict_ingress:ingress:prod:web:service:prod:web:ingress_exposes_service"].blocked_path_ids == {"path-a"}


def test_select_candidates_breaks_equal_scores_by_lower_fix_cost_then_candidate_id():
    optimizer = RemediationOptimizer()
    risky_paths = [
        {"path_id": "path-a", "raw_final_risk": 1.0, "path_index": 0, "path": ["a", "b"], "edges": []},
        {"path_id": "path-b", "raw_final_risk": 2.0 ** 1.2, "path_index": 1, "path": ["c", "d"], "edges": []},
        {"path_id": "path-c", "raw_final_risk": 1.0, "path_index": 2, "path": ["e", "f"], "edges": []},
    ]

    candidates = {
        "z-low-cost": RemediationCandidate(
            id="z-low-cost",
            edge_source="src:z",
            edge_target="dst:z",
            edge_type="pod_mounts_secret",
            fix_type="remove_secret_mount",
            fix_description="",
            fix_cost=1.0,
            blocked_path_ids={"path-a"},
            blocked_path_indices={0},
        ),
        "a-high-cost": RemediationCandidate(
            id="a-high-cost",
            edge_source="src:a",
            edge_target="dst:a",
            edge_type="restrict_ingress",
            fix_type="restrict_ingress",
            fix_description="",
            fix_cost=2.0,
            blocked_path_ids={"path-b"},
            blocked_path_indices={1},
        ),
        "b-same-cost": RemediationCandidate(
            id="b-same-cost",
            edge_source="src:b",
            edge_target="dst:b",
            edge_type="pod_mounts_secret",
            fix_type="remove_secret_mount",
            fix_description="",
            fix_cost=1.0,
            blocked_path_ids={"path-c"},
            blocked_path_indices={2},
        ),
        "a-same-cost": RemediationCandidate(
            id="a-same-cost",
            edge_source="src:c",
            edge_target="dst:c",
            edge_type="pod_mounts_secret",
            fix_type="remove_secret_mount",
            fix_description="",
            fix_cost=1.0,
            blocked_path_ids={"path-c"},
            blocked_path_indices={2},
        ),
    }

    selected = optimizer._select_candidates(candidates, risky_paths)

    assert [item["id"] for item in selected] == [
        "a-same-cost",
        "z-low-cost",
        "a-high-cost",
    ]


def test_select_candidates_covered_risk_uses_only_currently_uncovered_paths():
    optimizer = RemediationOptimizer()
    risky_paths = [
        {"path_id": "path-a", "raw_final_risk": 0.8, "path_index": 0, "path": ["a", "b"], "edges": []},
        {"path_id": "path-b", "raw_final_risk": 0.7, "path_index": 1, "path": ["c", "d"], "edges": []},
        {"path_id": "path-c", "raw_final_risk": 0.4, "path_index": 2, "path": ["e", "f"], "edges": []},
    ]
    candidates = {
        "candidate-shared": RemediationCandidate(
            id="candidate-shared",
            edge_source="src:shared",
            edge_target="dst:shared",
            edge_type="pod_mounts_secret",
            fix_type="remove_secret_mount",
            fix_description="",
            fix_cost=1.4,
            blocked_path_ids={"path-a", "path-b"},
            blocked_path_indices={0, 1},
        ),
        "candidate-overlap": RemediationCandidate(
            id="candidate-overlap",
            edge_source="src:overlap",
            edge_target="dst:overlap",
            edge_type="pod_mounts_secret",
            fix_type="remove_secret_mount",
            fix_description="",
            fix_cost=1.4,
            blocked_path_ids={"path-b", "path-c"},
            blocked_path_indices={1, 2},
        ),
    }

    selected = optimizer._select_candidates(candidates, risky_paths)

    assert [item["id"] for item in selected] == [
        "candidate-shared",
        "candidate-overlap",
    ]
    assert selected[0]["covered_risk"] == 1.5
    assert selected[1]["covered_risk"] == 0.4
