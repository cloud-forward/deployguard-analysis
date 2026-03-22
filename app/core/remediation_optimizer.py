"""
Greedy remediation optimization over risky attack paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx


FIX_COST_BY_TYPE: dict[str, float] = {
    "delete_resource": 3.5,
    "remove_role_binding": 1.5,
    "apply_network_policy": 1.8,
    "restrict_iam_policy": 2.0,
    "change_service_account": 1.7,
    "remove_secret_mount": 1.6,
    "restrict_ingress": 1.0,
    "remove_privileged": 2.2,
    "rotate_credentials": 1.9,
}

EDGE_FIX_TYPE_MAP: dict[str, tuple[str, str]] = {
    "ingress_exposes_service": (
        "restrict_ingress",
        "Restrict the ingress route to remove this exposure path.",
    ),
    "service_account_bound_role": (
        "remove_role_binding",
        "Remove or narrow the role binding that grants this service account access.",
    ),
    "service_account_bound_cluster_role": (
        "remove_role_binding",
        "Remove or narrow the cluster role binding that grants this service account access.",
    ),
    "lateral_move": (
        "apply_network_policy",
        "Apply network controls to block this lateral movement step.",
    ),
    "service_account_assumes_iam_role": (
        "restrict_iam_policy",
        "Restrict the IAM trust or attached policy enabling this cross-domain access.",
    ),
    "instance_profile_assumes": (
        "restrict_iam_policy",
        "Restrict the IAM trust or attached policy enabling this instance profile access.",
    ),
    "iam_role_access_resource": (
        "restrict_iam_policy",
        "Restrict the IAM policy that grants this resource access.",
    ),
    "iam_user_access_resource": (
        "restrict_iam_policy",
        "Restrict the IAM policy that grants this resource access.",
    ),
    "pod_uses_service_account": (
        "change_service_account",
        "Change the pod to use a less-privileged service account.",
    ),
    "pod_mounts_secret": (
        "remove_secret_mount",
        "Remove the secret mount or replace it with a safer delivery mechanism.",
    ),
    "pod_uses_env_from_secret": (
        "remove_secret_mount",
        "Remove secret-backed environment injection from this path.",
    ),
    "escapes_to": (
        "remove_privileged",
        "Remove the privileged or escape-capable pod configuration enabling this node escape.",
    ),
    "exposes_token": (
        "rotate_credentials",
        "Rotate the exposed credential and remove the access path that leaks it.",
    ),
    "secret_contains_credentials": (
        "rotate_credentials",
        "Rotate the embedded credential and remove the secret-based credential exposure.",
    ),
    "secret_contains_aws_credentials": (
        "rotate_credentials",
        "Rotate the exposed AWS credential and remove the secret-based credential exposure.",
    ),
}


@dataclass
class RemediationCandidate:
    id: str
    edge_source: str
    edge_target: str
    edge_type: str
    fix_type: str
    fix_description: str
    fix_cost: float
    metadata: dict[str, Any] = field(default_factory=dict)
    blocked_path_ids: set[str] = field(default_factory=set)
    blocked_path_indices: set[int] = field(default_factory=set)


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
                    "blocked_paths": 0,
                    "total_raw_final_risk": 0.0,
                    "blocked_raw_final_risk": 0.0,
                },
                "recommendations": [],
            }

        candidates = self._build_candidates(risky_paths, graph)
        selected = self._select_candidates(candidates, risky_paths)

        total_risk = round(sum(path["raw_final_risk"] for path in risky_paths), 6)
        blocked_path_ids = {
            path_id
            for item in selected
            for path_id in item["blocked_path_ids"]
        }
        blocked_risk = round(
            sum(path["raw_final_risk"] for path in risky_paths if path["path_id"] in blocked_path_ids),
            6,
        )

        return {
            "summary": {
                "candidate_count": len(candidates),
                "selected_count": len(selected),
                "total_paths": len(risky_paths),
                "blocked_paths": len(blocked_path_ids),
                "total_raw_final_risk": total_risk,
                "blocked_raw_final_risk": blocked_risk,
            },
            "recommendations": selected,
        }

    def _normalize_paths(self, enriched_paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for index, item in enumerate(enriched_paths):
            path = item.get("path")
            edges = item.get("edges")
            path_id = item.get("path_id") or f"path:{index}:{'->'.join(str(node_id) for node_id in path or [])}"
            raw_final_risk = item.get("raw_final_risk", item.get("risk_score"))

            if not isinstance(path, list) or len(path) < 2:
                continue
            if not isinstance(edges, list) or not edges:
                continue

            try:
                risk = float(raw_final_risk)
            except (TypeError, ValueError):
                continue

            if risk <= 0:
                continue

            normalized.append(
                {
                    "path_index": index,
                    "path_id": str(path_id),
                    "path": [str(node_id) for node_id in path],
                    "raw_final_risk": risk,
                    "edges": [
                        {
                            "source": str(edge.get("source", "")),
                            "target": str(edge.get("target", "")),
                            "type": str(edge.get("type", "")),
                        }
                        for edge in edges
                        if edge.get("source") and edge.get("target") and edge.get("type")
                    ],
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

            for edge in path_item["edges"]:
                candidate = self._candidate_from_edge(edge, graph)
                if candidate is None or candidate.id in seen_candidate_ids:
                    continue
                seen_candidate_ids.add(candidate.id)

                existing = candidates.get(candidate.id)
                if existing is None:
                    existing = candidate
                    candidates[candidate.id] = existing

                existing.blocked_path_ids.add(path_item["path_id"])
                existing.blocked_path_indices.add(path_item["path_index"])

        return candidates

    def _candidate_from_edge(
        self,
        edge: dict[str, str],
        graph: nx.DiGraph,
    ) -> RemediationCandidate | None:
        edge_type = edge["type"]
        mapping = EDGE_FIX_TYPE_MAP.get(edge_type)
        if mapping is None:
            return None

        source = edge["source"]
        target = edge["target"]
        fix_type, fix_description = mapping

        metadata: dict[str, Any] = {}
        if source in graph:
            metadata["edge_source_type"] = graph.nodes[source].get("type")
        if target in graph:
            metadata["edge_target_type"] = graph.nodes[target].get("type")

        return RemediationCandidate(
            id=self._candidate_id(source, target, edge_type, fix_type),
            edge_source=source,
            edge_target=target,
            edge_type=edge_type,
            fix_type=fix_type,
            fix_description=fix_description,
            fix_cost=FIX_COST_BY_TYPE[fix_type],
            metadata=metadata,
        )

    def _select_candidates(
        self,
        candidates: dict[str, RemediationCandidate],
        risky_paths: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        path_risk_by_id = {
            path["path_id"]: float(path["raw_final_risk"])
            for path in risky_paths
        }
        uncovered = set(path_risk_by_id.keys())
        selected: list[dict[str, Any]] = []

        while uncovered:
            best: RemediationCandidate | None = None
            best_uncovered: set[str] = set()
            best_score = 0.0

            for candidate in candidates.values():
                covered_now = candidate.blocked_path_ids & uncovered
                if not covered_now:
                    continue

                covered_total_risk = sum(path_risk_by_id[path_id] for path_id in covered_now)
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

            cumulative_risk_reduction = round(
                sum(path_risk_by_id[path_id] for path_id in best_uncovered),
                6,
            )
            selected.append(
                {
                    "id": best.id,
                    "edge_source": best.edge_source,
                    "edge_target": best.edge_target,
                    "edge_type": best.edge_type,
                    "fix_type": best.fix_type,
                    "fix_description": best.fix_description,
                    "fix_cost": best.fix_cost,
                    "blocked_path_ids": sorted(best_uncovered),
                    "blocked_path_indices": sorted(
                        path["path_index"]
                        for path in risky_paths
                        if path["path_id"] in best_uncovered
                    ),
                    "cumulative_risk_reduction": cumulative_risk_reduction,
                    "edge_score": round(
                        cumulative_risk_reduction / (best.fix_cost ** 1.2),
                        6,
                    ),
                    "metadata": dict(best.metadata),
                }
            )
            uncovered -= best_uncovered

        return selected

    @staticmethod
    def _candidate_id(source: str, target: str, edge_type: str, fix_type: str) -> str:
        return f"{fix_type}:{source}:{target}:{edge_type}"
