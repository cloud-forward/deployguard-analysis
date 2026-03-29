"""
Greedy remediation optimization over risky attack paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx


FIX_COST_BY_TYPE: dict[str, float] = {
    "delete_resource": 3.5,
    "remove_role_binding": 1.8,
    "apply_network_policy": 2.2,
    "restrict_iam_policy": 2.4,
    "change_service_account": 1.6,
    "remove_secret_mount": 1.4,
    "restrict_ingress": 3.2,
    "remove_privileged": 3.0,
    "rotate_credentials": 1.7,
}

FIX_TYPE_DISPLAY_MAP_KO: dict[str, str] = {
    "delete_resource": "리소스를 삭제",
    "remove_role_binding": "role binding을 제거하거나 범위를 축소",
    "apply_network_policy": "네트워크 접근 제어를 적용",
    "restrict_iam_policy": "IAM 정책을 제한",
    "change_service_account": "workload의 service account를 변경",
    "remove_secret_mount": "secret mount를 제거",
    "restrict_ingress": "Ingress 노출을 제한",
    "remove_privileged": "Privileged 또는 탈출 가능 Pod 설정을 제거",
    "rotate_credentials": "노출된 자격 증명을 교체",
}

EDGE_FIX_COST_OVERRIDE: dict[str, float] = {
    "service_account_bound_role": 1.8,
    "service_account_bound_cluster_role": 2.8,
}

EDGE_FIX_TYPE_MAP: dict[str, tuple[str, str]] = {
    "ingress_exposes_service": (
        "restrict_ingress",
        "Ingress 노출을 제한",
    ),
    "service_account_bound_role": (
        "remove_role_binding",
        "role binding을 제거하거나 범위를 축소",
    ),
    "service_account_bound_cluster_role": (
        "remove_role_binding",
        "cluster role binding을 제거하거나 범위를 축소",
    ),
    "lateral_move": (
        "apply_network_policy",
        "네트워크 접근 제어를 적용",
    ),
    "service_account_assumes_iam_role": (
        "restrict_iam_policy",
        "IAM trust policy 또는 연결된 권한을 제한",
    ),
    "instance_profile_assumes": (
        "restrict_iam_policy",
        "instance profile의 trust policy 또는 연결된 권한을 제한",
    ),
    "iam_principal_assumes_iam_role": (
        "restrict_iam_policy",
        "AssumeRole 권한 또는 신뢰 정책을 제한",
    ),
    "iam_role_access_resource": (
        "restrict_iam_policy",
        "IAM 정책을 제한",
    ),
    "iam_user_access_resource": (
        "restrict_iam_policy",
        "IAM 정책을 제한",
    ),
    "pod_uses_service_account": (
        "change_service_account",
        "workload의 service account를 변경",
    ),
    "pod_mounts_secret": (
        "remove_secret_mount",
        "secret mount를 제거",
    ),
    "pod_uses_env_from_secret": (
        "remove_secret_mount",
        "secret 기반 환경 변수 주입을 제거",
    ),
    "escapes_to": (
        "remove_privileged",
        "Privileged 또는 탈출 가능 Pod 설정을 제거",
    ),
    "exposes_token": (
        "rotate_credentials",
        "노출된 자격 증명을 교체",
    ),
    "secret_contains_credentials": (
        "rotate_credentials",
        "노출된 자격 증명을 교체",
    ),
    "secret_contains_aws_credentials": (
        "rotate_credentials",
        "노출된 AWS 자격 증명을 교체",
    ),
}

EDGE_IMPACT_REASON_MAP: dict[str, str] = {
    "ingress_exposes_service": "이 공개 Ingress 단계가 내부 서비스를 노출하기 때문입니다",
    "service_account_bound_role": "이 role binding이 service account에 추가 권한을 부여하기 때문입니다",
    "service_account_bound_cluster_role": "이 cluster role binding이 service account에 추가 권한을 부여하기 때문입니다",
    "lateral_move": "이 edge가 workload 또는 네트워크 구간 사이의 lateral movement를 허용하기 때문입니다",
    "service_account_assumes_iam_role": "이 trust path를 통해 Kubernetes identity가 IAM Role을 Assume할 수 있기 때문입니다",
    "instance_profile_assumes": "이 trust path를 통해 instance profile이 더 넓은 IAM 권한을 획득할 수 있기 때문입니다",
    "iam_principal_assumes_iam_role": "이 IAM 주체가 대상 IAM Role을 명시적으로 Assume할 수 있기 때문입니다",
    "iam_role_access_resource": "이 edge가 direct resource access를 허용하기 때문입니다",
    "iam_user_access_resource": "이 edge가 direct resource access를 허용하기 때문입니다",
    "pod_uses_service_account": "이 workload가 path 상의 service account 권한을 상속받기 때문입니다",
    "pod_mounts_secret": "이 workload가 mount된 secret 값을 읽을 수 있기 때문입니다",
    "pod_uses_env_from_secret": "이 workload가 secret 기반 환경 변수 값을 읽을 수 있기 때문입니다",
    "escapes_to": "이 edge가 node로의 container escape 단계를 나타내기 때문입니다",
    "exposes_token": "이 edge가 이후 path에서 재사용 가능한 자격 증명을 노출하기 때문입니다",
    "secret_contains_credentials": "이 secret에 재사용 가능한 자격 증명이 포함되어 있기 때문입니다",
    "secret_contains_aws_credentials": "이 secret에 재사용 가능한 AWS 자격 증명이 포함되어 있기 때문입니다",
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

        fix_cost = EDGE_FIX_COST_OVERRIDE.get(edge_type, FIX_COST_BY_TYPE[fix_type])

        metadata: dict[str, Any] = {}
        if source in graph:
            metadata["edge_source_type"] = graph.nodes[source].get("type")
        if target in graph:
            metadata["edge_target_type"] = graph.nodes[target].get("type")
        metadata["base_action"] = base_action
        metadata["impact_reason"] = EDGE_IMPACT_REASON_MAP.get(edge_type, "이 edge가 attack path를 계속 열어 두기 때문입니다")
        metadata["effective_fix_cost"] = fix_cost

        return RemediationCandidate(
            id=self._candidate_id(source, target, edge_type, fix_type),
            edge_source=source,
            edge_target=target,
            edge_type=edge_type,
            fix_type=fix_type,
            fix_description="",
            fix_cost=fix_cost,
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
        cumulative_removed_raw_risk = 0.0
        total_raw_risk = round(sum(path_risk_by_id.values()), 6)

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
            cumulative_removed_raw_risk = round(cumulative_removed_raw_risk + covered_risk, 6)
            cumulative_risk_reduction = round(
                (cumulative_removed_raw_risk / total_raw_risk) if total_raw_risk > 0 else 0.0,
                6,
            )
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
        impact_reason = str(candidate.metadata.get("impact_reason") or "이 edge가 attack path를 계속 열어 두기 때문입니다")
        source_ref = self._describe_node_ref(candidate.edge_source, candidate.metadata.get("edge_source_type"))
        target_ref = self._describe_node_ref(candidate.edge_target, candidate.metadata.get("edge_target_type"))

        return (
            f"{source_ref} -> {target_ref} 변경: {base_action}. "
            f"중요한 이유: {impact_reason} "
            f"예상 효과: risky path {blocked_path_count}개를 차단하고, Raw risk를 {covered_risk:.2f}만큼 줄입니다 "
            f"(cumulative reduction ratio {cumulative_risk_reduction:.2f})."
        )

    @staticmethod
    def _describe_node_ref(node_id: str, node_type: Any) -> str:
        normalized_type = str(node_type or "").replace("_", " ").strip()
        if normalized_type:
            return f"{normalized_type} `{node_id}`"
        return f"`{node_id}`"

    @staticmethod
    def _fallback_action(fix_type: str) -> str:
        return FIX_TYPE_DISPLAY_MAP_KO.get(fix_type, "권장 변경을 적용")

    @staticmethod
    def _candidate_id(source: str, target: str, edge_type: str, fix_type: str) -> str:
        return f"{fix_type}:{source}:{target}:{edge_type}"
