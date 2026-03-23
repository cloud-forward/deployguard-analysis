"""
SQLAlchemy implementation of AnalysisJobRepository.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID, uuid4
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.gateway.models import (
    AnalysisJob,
    AttackPath,
    AttackPathEdge,
    GraphSnapshot,
    RemediationRecommendation,
)


class SqlAlchemyAnalysisJobRepository(AnalysisJobRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create_job(self, target_id: str, params: Dict[str, Any]) -> str:
        return "job_stub"

    async def mark_started(self, job_id: str) -> None:
        await self.mark_running(job_id)

    async def mark_completed(self, job_id: str, summary: Dict[str, Any]) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "completed"
        job.current_step = None
        job.error_message = None
        job.completed_at = datetime.utcnow()
        await self._session.commit()

    async def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def mark_running(self, job_id: str, current_step: str | None = None) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "running"
        job.current_step = current_step
        job.error_message = None
        if job.started_at is None:
            job.started_at = datetime.utcnow()
        await self._session.commit()

    async def update_current_step(self, job_id: str, current_step: str) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "running"
        job.current_step = current_step
        await self._session.commit()

    async def mark_failed(self, job_id: str, error_message: str) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "failed"
        job.current_step = None
        job.error_message = error_message
        job.completed_at = datetime.utcnow()
        await self._session.commit()

    async def get_analysis_job(self, job_id: str) -> AnalysisJob | None:
        return await self._session.get(AnalysisJob, job_id)

    async def list_analysis_jobs(
        self,
        cluster_id: str | UUID,
        status: str | None = None,
    ) -> list[AnalysisJob]:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        query = (
            select(AnalysisJob)
            .where(AnalysisJob.cluster_id == normalized_cluster_id)
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
        )
        if status is not None:
            query = query.where(AnalysisJob.status == status)
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def create_analysis_job(
        self,
        cluster_id: str | UUID,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        expected_scans: list[str],
    ) -> str:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        job = AnalysisJob(
            cluster_id=normalized_cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
            expected_scans=list(expected_scans),
            status="pending",
        )
        self._session.add(job)
        await self._session.commit()
        await self._session.refresh(job)
        return job.id

    async def persist_attack_paths(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str | None,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        attack_paths: list[Dict[str, Any]],
    ) -> str:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        persisted_graph_id = await self._ensure_graph_snapshot(graph_id, normalized_cluster_id)

        path_ids_subquery = select(AttackPath.id).where(AttackPath.graph_id == persisted_graph_id)
        await self._session.execute(delete(AttackPathEdge).where(AttackPathEdge.path_id.in_(path_ids_subquery)))
        await self._session.execute(delete(AttackPath).where(AttackPath.graph_id == persisted_graph_id))

        matching_job = await self._session.scalar(
            select(AnalysisJob)
            .where(
                AnalysisJob.cluster_id == normalized_cluster_id,
                AnalysisJob.k8s_scan_id == k8s_scan_id,
                AnalysisJob.aws_scan_id == aws_scan_id,
                AnalysisJob.image_scan_id == image_scan_id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
        )
        if matching_job is not None:
            matching_job.graph_id = persisted_graph_id

        for path in attack_paths:
            path_id = str(path["path_id"])
            node_ids = [str(node_id) for node_id in path.get("path", [])]
            edges = list(path.get("edges", []))
            edge_ids = [self._edge_id(path_id, index) for index, _ in enumerate(edges)]

            attack_path = AttackPath(
                graph_id=persisted_graph_id,
                path_id=path_id,
                title=self._path_title(path),
                risk_level=self._risk_level(path.get("raw_final_risk", path.get("risk_score"))),
                risk_score=self._as_float(path.get("risk_score")),
                raw_final_risk=self._as_float(path.get("raw_final_risk", path.get("risk_score"))),
                hop_count=max(len(node_ids) - 1, 0),
                entry_node_id=node_ids[0] if node_ids else None,
                target_node_id=node_ids[-1] if node_ids else None,
                node_ids=node_ids,
                edge_ids=edge_ids,
            )
            self._session.add(attack_path)
            await self._session.flush()

            for index, edge in enumerate(edges):
                self._session.add(
                    AttackPathEdge(
                        id=edge_ids[index],
                        path_id=attack_path.id,
                        sequence=index,
                        source_node_id=str(edge.get("source", "")),
                        target_node_id=str(edge.get("target", "")),
                        edge_type=str(edge.get("type", "")),
                    )
                )

        await self._session.commit()
        return persisted_graph_id

    async def persist_remediation_recommendations(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str | None,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        remediation_optimization: Dict[str, Any],
    ) -> None:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        persisted_graph_id = await self._ensure_graph_snapshot(graph_id, normalized_cluster_id)

        matching_job = await self._session.scalar(
            select(AnalysisJob)
            .where(
                AnalysisJob.cluster_id == normalized_cluster_id,
                AnalysisJob.k8s_scan_id == k8s_scan_id,
                AnalysisJob.aws_scan_id == aws_scan_id,
                AnalysisJob.image_scan_id == image_scan_id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
        )
        if matching_job is not None:
            matching_job.graph_id = persisted_graph_id

        await self._session.execute(
            delete(RemediationRecommendation).where(RemediationRecommendation.graph_id == persisted_graph_id)
        )

        recommendations = list(remediation_optimization.get("recommendations", []))
        for rank, recommendation in enumerate(recommendations):
            self._session.add(
                RemediationRecommendation(
                    graph_id=persisted_graph_id,
                    recommendation_id=str(recommendation.get("id", f"recommendation:{rank}")),
                    recommendation_rank=rank,
                    edge_source=self._as_str(recommendation.get("edge_source")),
                    edge_target=self._as_str(recommendation.get("edge_target")),
                    edge_type=self._as_str(recommendation.get("edge_type")),
                    fix_type=self._as_str(recommendation.get("fix_type")),
                    fix_description=self._as_str(recommendation.get("fix_description")),
                    blocked_path_ids=self._as_str_list(recommendation.get("blocked_path_ids")),
                    blocked_path_indices=self._as_int_list(recommendation.get("blocked_path_indices")),
                    fix_cost=self._as_float(recommendation.get("fix_cost")),
                    edge_score=self._as_float(recommendation.get("edge_score")),
                    covered_risk=self._as_float(recommendation.get("covered_risk")),
                    cumulative_risk_reduction=self._as_float(recommendation.get("cumulative_risk_reduction")),
                    metadata_json=self._as_dict(recommendation.get("metadata")),
                )
            )

        await self._session.commit()

    async def _ensure_graph_snapshot(self, graph_id: str | None, cluster_id: str) -> str:
        normalized_graph_id = self._normalize_graph_id(graph_id)
        if normalized_graph_id is not None:
            snapshot = await self._session.get(GraphSnapshot, normalized_graph_id)
            if snapshot is None:
                snapshot = GraphSnapshot(id=normalized_graph_id, cluster_id=cluster_id)
                self._session.add(snapshot)
                await self._session.flush()
            return snapshot.id

        snapshot = GraphSnapshot(cluster_id=cluster_id)
        self._session.add(snapshot)
        await self._session.flush()
        return snapshot.id

    @staticmethod
    def _risk_level(value: Any) -> str:
        score = SqlAlchemyAnalysisJobRepository._as_float(value) or 0.0
        if score >= 0.9:
            return "critical"
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        if score > 0:
            return "low"
        return "none"

    @staticmethod
    def _path_title(path: Dict[str, Any]) -> str:
        nodes = [str(node_id) for node_id in path.get("path", [])]
        if len(nodes) >= 2:
            return f"{nodes[0]} -> {nodes[-1]}"
        return str(path.get("path_id", "attack-path"))

    @staticmethod
    def _edge_id(path_id: str, edge_index: int) -> str:
        return str(uuid4())

    @staticmethod
    def _as_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_str(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, dict) else {}

    @staticmethod
    def _as_str_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value]

    @staticmethod
    def _as_int_list(value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        normalized: list[int] = []
        for item in value:
            try:
                normalized.append(int(item))
            except (TypeError, ValueError):
                continue
        return normalized

    @staticmethod
    def _normalize_graph_id(value: Any) -> str | None:
        if value is None:
            return None
        try:
            return str(UUID(str(value)))
        except (TypeError, ValueError):
            return None
