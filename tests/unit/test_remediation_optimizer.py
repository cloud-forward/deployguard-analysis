import networkx as nx

from app.core.remediation_optimizer import RemediationOptimizer


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
    assert result["recommendations"][0]["cumulative_risk_reduction"] == 1.5


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
    assert result["recommendations"][0]["covered_risk"] == 0.8
    assert result["recommendations"][0]["cumulative_risk_reduction"] == 0.8
    assert result["recommendations"][1]["covered_risk"] == 0.7
    assert result["recommendations"][1]["cumulative_risk_reduction"] == 1.5
    assert any(item.startswith("restrict_ingress:") for item in recommendation_ids)
    assert any(item.startswith("remove_privileged:") for item in recommendation_ids)
