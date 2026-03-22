import networkx as nx

from app.core.remediation_optimizer import RemediationOptimizer


def test_optimizer_prefers_shared_low_cost_breakpoint():
    graph = nx.DiGraph()
    graph.add_node("ingress:prod:web", type="ingress")
    graph.add_node("service_account:prod:api", type="service_account")
    graph.add_node("role:prod:reader", type="role")
    graph.add_node("iam:123:AppRole", type="iam_role")

    enriched_paths = [
        {
            "path": ["ingress:prod:web", "service_account:prod:api", "iam:123:AppRole"],
            "risk_score": 0.9,
            "length": 3,
            "edges": [],
        },
        {
            "path": ["ingress:prod:web", "role:prod:reader", "iam:123:AppRole"],
            "risk_score": 0.6,
            "length": 3,
            "edges": [],
        },
    ]

    result = RemediationOptimizer().optimize(enriched_paths, graph)

    assert result["summary"]["total_paths"] == 2
    assert result["summary"]["covered_paths"] == 2
    assert result["recommendations"][0]["target_node_id"] == "ingress:prod:web"
    assert result["recommendations"][0]["covers_path_indices"] == [0, 1]


def test_optimizer_skips_non_control_assets_and_selects_multiple_breakpoints_when_needed():
    graph = nx.DiGraph()
    graph.add_node("ingress:prod:web", type="ingress")
    graph.add_node("node:worker-1", type="node")
    graph.add_node("s3:123:data", type="s3_bucket")
    graph.add_node("iam:123:BatchRole", type="iam_role")

    enriched_paths = [
        {
            "path": ["ingress:prod:web", "s3:123:data"],
            "risk_score": 0.8,
            "length": 2,
            "edges": [],
        },
        {
            "path": ["node:worker-1", "iam:123:BatchRole"],
            "risk_score": 0.7,
            "length": 2,
            "edges": [],
        },
    ]

    result = RemediationOptimizer().optimize(enriched_paths, graph)

    recommendation_ids = [item["target_node_id"] for item in result["recommendations"]]

    assert "s3:123:data" not in recommendation_ids
    assert result["summary"]["selected_count"] == 2
    assert recommendation_ids == ["ingress:prod:web", "iam:123:BatchRole"]
