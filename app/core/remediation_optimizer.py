"""
Greedy remediation optimization over risky attack paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx


CONTROL_NODE_TYPES = {
    "ingress",
    "service_account",
    "role",
    "cluster_role",
    "node",
    "node_credential",
    "iam_role",
}

FIX_COST_BY_NODE_TYPE: dict[str, float] = {
    "ingress": 1.0,
    "service_account": 1.5,
    "role": 2.0,
    "cluster_role": 3.0,
    "node": 3.0,
    "node_credential": 2.5,
    "iam_role": 2.0,
}

ACTION_BY_NODE_TYPE: dict[str, str] = {
    "ingress": "restrict_ingress",
    "service_account": "restrict_service_account",
    "role": "tighten_role",
    "cluster_role": "tighten_cluster_role",
    "node": "harden_node",
    "node_credential": "rotate_node_credential",
    "iam_role": "tighten_iam_role",
}

TITLE_BY_NODE_TYPE: dict[str, str] = {
    "ingress": "Restrict ingress exposure",
    "service_account": "Restrict service account privileges",
    "role": "Tighten role permissions",
    "cluster_role": "Tighten cluster role permissions",
    "node": "Harden node access",
    "node_credential": "Rotate node credential",
    "iam_role": "Tighten IAM role permissions",
}


@dataclass
class RemediationCandidate:
    id: str
    title: str
    action_type: str
    target_node_id: str
    target_node_type: str
    fix_cost: float
    metadata: dict[str, Any] = field(default_factory=dict)
    covers_path_keys: set[str] = field(default_factory=set)
    covers_path_indices: set[int] = field(default_factory=set)


class RemediationOptimizer:
    """Select a minimal, high-impact remediation set using greedy weighted set cover."""

    def optimize(
        self,
        enriched_paths: list[dict[str, Any]],
        graph: nx.DiGraph,
    ) -> dict[str, Any]:
        risky_paths = self._normalize_paths(enriched_paths)
        if not risky_paths:
            return {
                "summary": {
                    "candidate_count": 0,
                    "selected_count": 0,
                    "total_paths": 0,
                    "covered_paths": 0,
                    "total_risk": 0.0,
                    "covered_risk": 0.0,
                },
                "recommendations": [],
            }

        candidates = self._build_candidates(risky_paths, graph)
        selected = self._select_candidates(candidates, risky_paths)

        total_risk = round(sum(path["risk_score"] for path in risky_paths), 6)
        covered_path_keys = {
            path_key
            for item in selected
            for path_key in item["covers_path_keys"]
        }
        covered_risk = round(
            sum(path["risk_score"] for path in risky_paths if path["path_key"] in covered_path_keys),
            6,
        )

        return {
            "summary": {
                "candidate_count": len(candidates),
                "selected_count": len(selected),
                "total_paths": len(risky_paths),
                "covered_paths": len(covered_path_keys),
                "total_risk": total_risk,
                "covered_risk": covered_risk,
            },
            "recommendations": selected,
        }

    def _normalize_paths(self, enriched_paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for index, item in enumerate(enriched_paths):
            path = item.get("path")
            risk_score = item.get("risk_score")
            if not isinstance(path, list) or len(path) < 2:
                continue

            try:
                risk = float(risk_score)
            except (TypeError, ValueError):
                continue

            if risk <= 0:
                continue

            path_key = f"path:{index}:{'->'.join(str(node_id) for node_id in path)}"
            normalized.append(
                {
                    "path_index": index,
                    "path_key": path_key,
                    "path": [str(node_id) for node_id in path],
                    "risk_score": risk,
                    "edges": list(item.get("edges", [])),
                }
            )

        return normalized

    def _build_candidates(
        self,
        risky_paths: list[dict[str, Any]],
        graph: nx.DiGraph,
    ) -> dict[str, RemediationCandidate]:
        candidates: dict[str, RemediationCandidate] = {}

        for path_item in risky_paths:
            seen_candidate_ids: set[str] = set()

            for node_id in path_item["path"]:
                if node_id not in graph:
                    continue

                node_type = str(graph.nodes[node_id].get("type", "")).strip().lower()
                if node_type not in CONTROL_NODE_TYPES:
                    continue

                candidate_id = self._candidate_id(node_type, node_id)
                if candidate_id in seen_candidate_ids:
                    continue
                seen_candidate_ids.add(candidate_id)

                candidate = candidates.get(candidate_id)
                if candidate is None:
                    candidate = RemediationCandidate(
                        id=candidate_id,
                        title=TITLE_BY_NODE_TYPE[node_type],
                        action_type=ACTION_BY_NODE_TYPE[node_type],
                        target_node_id=node_id,
                        target_node_type=node_type,
                        fix_cost=FIX_COST_BY_NODE_TYPE[node_type],
                        metadata={"node_type": node_type},
                    )
                    candidates[candidate_id] = candidate

                candidate.covers_path_keys.add(path_item["path_key"])
                candidate.covers_path_indices.add(path_item["path_index"])

        return candidates

    def _select_candidates(
        self,
        candidates: dict[str, RemediationCandidate],
        risky_paths: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        path_risk_by_key = {
            path["path_key"]: float(path["risk_score"])
            for path in risky_paths
        }
        uncovered = set(path_risk_by_key.keys())
        selected: list[dict[str, Any]] = []

        while uncovered:
            best: RemediationCandidate | None = None
            best_uncovered: set[str] = set()
            best_score = 0.0

            for candidate in candidates.values():
                covered_now = candidate.covers_path_keys & uncovered
                if not covered_now:
                    continue

                covered_total_risk = sum(path_risk_by_key[path_key] for path_key in covered_now)
                score = covered_total_risk / (candidate.fix_cost ** 1.2)

                if (
                    score > best_score
                    or (
                        score == best_score
                        and best is not None
                        and (candidate.fix_cost, candidate.id) < (best.fix_cost, best.id)
                    )
                    or best is None
                ):
                    best = candidate
                    best_uncovered = covered_now
                    best_score = score

            if best is None:
                break

            covered_risk = round(sum(path_risk_by_key[path_key] for path_key in best_uncovered), 6)
            efficiency = round(covered_risk / (best.fix_cost ** 1.2), 6)
            selected.append(
                {
                    "id": best.id,
                    "title": best.title,
                    "action_type": best.action_type,
                    "target_node_id": best.target_node_id,
                    "target_node_type": best.target_node_type,
                    "target_edge": None,
                    "fix_cost": best.fix_cost,
                    "covers_path_keys": sorted(best_uncovered),
                    "covers_path_indices": sorted(
                        path["path_index"]
                        for path in risky_paths
                        if path["path_key"] in best_uncovered
                    ),
                    "covered_risk": covered_risk,
                    "efficiency": efficiency,
                    "metadata": dict(best.metadata),
                }
            )
            uncovered -= best_uncovered

        return selected

    @staticmethod
    def _candidate_id(node_type: str, node_id: str) -> str:
        return f"{ACTION_BY_NODE_TYPE[node_type]}:{node_id}"
