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
        "restrict ingress exposure",
    ),
    "service_account_bound_role": (
        "remove_role_binding",
        "remove or narrow the role binding",
    ),
    "service_account_bound_cluster_role": (
        "remove_role_binding",
        "remove or narrow the cluster role binding",
    ),
    "lateral_move": (
        "apply_network_policy",
        "apply network controls",
    ),
    "service_account_assumes_iam_role": (
        "restrict_iam_policy",
        "restrict the IAM trust or attached policy",
    ),
    "instance_profile_assumes": (
        "restrict_iam_policy",
        "restrict the instance profile trust or attached policy",
    ),
    "iam_role_access_resource": (
        "restrict_iam_policy",
        "restrict the IAM policy",
    ),
    "iam_user_access_resource": (
        "restrict_iam_policy",
        "restrict the IAM policy",
    ),
    "pod_uses_service_account": (
        "change_service_account",
        "change the workload service account",
    ),
    "pod_mounts_secret": (
        "remove_secret_mount",
        "remove the secret mount",
    ),
    "pod_uses_env_from_secret": (
        "remove_secret_mount",
        "remove secret-backed environment injection",
    ),
    "escapes_to": (
        "remove_privileged",
        "remove privileged or escape-capable pod settings",
    ),
    "exposes_token": (
        "rotate_credentials",
        "rotate the exposed credential",
    ),
    "secret_contains_credentials": (
        "rotate_credentials",
        "rotate the exposed credential",
    ),
    "secret_contains_aws_credentials": (
        "rotate_credentials",
        "rotate the exposed AWS credential",
    ),
}

EDGE_IMPACT_REASON_MAP: dict[str, str] = {
    "ingress_exposes_service": "this public ingress step exposes an internal service",
    "service_account_bound_role": "this binding grants the service account additional permissions",
    "service_account_bound_cluster_role": "this cluster-wide binding grants the service account additional permissions",
    "lateral_move": "this edge allows lateral movement between workloads or network zones",
    "service_account_assumes_iam_role": "this trust path lets a Kubernetes identity assume an IAM role",
    "instance_profile_assumes": "this trust path lets the instance profile assume broader IAM access",
    "iam_role_access_resource": "this policy edge grants direct resource access",
    "iam_user_access_resource": "this policy edge grants direct resource access",
    "pod_uses_service_account": "this workload inherits the service account permissions on the path",
    "pod_mounts_secret": "this workload can read mounted secret material",
    "pod_uses_env_from_secret": "this workload can read secret-backed environment values",
    "escapes_to": "this edge represents a container escape step to the node",
    "exposes_token": "this edge leaks a credential that can be reused later in the path",
    "secret_contains_credentials": "this secret contains reusable credentials",
    "secret_contains_aws_credentials": "this secret contains reusable AWS credentials",
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
        fix_type, base_action = mapping

        metadata: dict[str, Any] = {}
        if source in graph:
            metadata["edge_source_type"] = graph.nodes[source].get("type")
        if target in graph:
            metadata["edge_target_type"] = graph.nodes[target].get("type")
        metadata["base_action"] = base_action
        metadata["impact_reason"] = EDGE_IMPACT_REASON_MAP.get(edge_type, "this edge keeps the attack path open")

        return RemediationCandidate(
            id=self._candidate_id(source, target, edge_type, fix_type),
            edge_source=source,
            edge_target=target,
            edge_type=edge_type,
            fix_type=fix_type,
            fix_description="",
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
        cumulative_risk_reduction = 0.0

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

            covered_risk = round(
                sum(path_risk_by_id[path_id] for path_id in best_uncovered),
                6,
            )
            cumulative_risk_reduction = round(cumulative_risk_reduction + covered_risk, 6)
            fix_description = self._build_fix_description(
                best,
                blocked_path_count=len(best_uncovered),
                covered_risk=covered_risk,
                cumulative_risk_reduction=cumulative_risk_reduction,
            )
            selected.append(
                {
                    "id": best.id,
                    "edge_source": best.edge_source,
                    "edge_target": best.edge_target,
                    "edge_type": best.edge_type,
                    "fix_type": best.fix_type,
                    "fix_description": fix_description,
                    "fix_cost": best.fix_cost,
                    "blocked_path_ids": sorted(best_uncovered),
                    "blocked_path_indices": sorted(
                        path["path_index"]
                        for path in risky_paths
                        if path["path_id"] in best_uncovered
                    ),
                    "covered_risk": covered_risk,
                    "cumulative_risk_reduction": cumulative_risk_reduction,
                    "edge_score": round(
                        covered_risk / (best.fix_cost ** 1.2),
                        6,
                    ),
                    "metadata": dict(best.metadata),
                }
            )
            uncovered -= best_uncovered

        return selected

    def _build_fix_description(
        self,
        candidate: RemediationCandidate,
        *,
        blocked_path_count: int,
        covered_risk: float,
        cumulative_risk_reduction: float,
    ) -> str:
        base_action = str(candidate.metadata.get("base_action") or self._fallback_action(candidate.fix_type))
        impact_reason = str(candidate.metadata.get("impact_reason") or "this edge keeps the attack path open")
        source_ref = self._describe_node_ref(candidate.edge_source, candidate.metadata.get("edge_source_type"))
        target_ref = self._describe_node_ref(candidate.edge_target, candidate.metadata.get("edge_target_type"))
        path_label = "path" if blocked_path_count == 1 else "paths"

        return (
            f"Change {source_ref} -> {target_ref}: {base_action}. "
            f"This matters because {impact_reason}. "
            f"Expected effect: block {blocked_path_count} risky {path_label} and reduce raw risk by {covered_risk:.2f} "
            f"(cumulative {cumulative_risk_reduction:.2f})."
        )

    @staticmethod
    def _describe_node_ref(node_id: str, node_type: Any) -> str:
        normalized_type = str(node_type or "").replace("_", " ").strip()
        if normalized_type:
            return f"{normalized_type} `{node_id}`"
        return f"`{node_id}`"

    @staticmethod
    def _fallback_action(fix_type: str) -> str:
        return fix_type.replace("_", " ")

    @staticmethod
    def _candidate_id(source: str, target: str, edge_type: str, fix_type: str) -> str:
        return f"{fix_type}:{source}:{target}:{edge_type}"
