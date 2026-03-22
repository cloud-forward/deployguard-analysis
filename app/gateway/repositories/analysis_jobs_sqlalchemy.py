"""
SQLAlchemy implementation of AnalysisJobRepository.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from uuid import UUID
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.gateway.models import AnalysisJob, AttackPath, AttackPathEdge, GraphSnapshot


class SqlAlchemyAnalysisJobRepository(AnalysisJobRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create_job(self, target_id: str, params: Dict[str, Any]) -> str:
        return "job_stub"

    async def mark_started(self, job_id: str) -> None:
        return None

    async def mark_completed(self, job_id: str, summary: Dict[str, Any]) -> None:
        return None

    async def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def create_analysis_job(self, cluster_id: str | UUID, k8s_scan_id: str, aws_scan_id: str, image_scan_id: str) -> str:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        job = AnalysisJob(
            cluster_id=normalized_cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
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
        graph_id: str,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        attack_paths: list[Dict[str, Any]],
    ) -> None:
        normalized_cluster_id = str(UUID(str(cluster_id)))

        snapshot = await self._session.get(GraphSnapshot, graph_id)
        if snapshot is None:
            self._session.add(GraphSnapshot(id=graph_id))
            await self._session.flush()

        await self._session.execute(delete(AttackPathEdge).where(AttackPathEdge.graph_id == graph_id))
        await self._session.execute(delete(AttackPath).where(AttackPath.graph_id == graph_id))

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
            matching_job.graph_id = graph_id

        for path in attack_paths:
            path_id = str(path["path_id"])
            node_ids = [str(node_id) for node_id in path.get("path", [])]
            edges = list(path.get("edges", []))
            edge_ids = [self._edge_id(path_id, index) for index, _ in enumerate(edges)]

            self._session.add(
                AttackPath(
                    graph_id=graph_id,
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
            )

            for index, edge in enumerate(edges):
                self._session.add(
                    AttackPathEdge(
                        graph_id=graph_id,
                        path_id=path_id,
                        edge_id=edge_ids[index],
                        edge_index=index,
                        source_node_id=str(edge.get("source", "")),
                        target_node_id=str(edge.get("target", "")),
                        edge_type=str(edge.get("type", "")),
                        metadata_json={},
                    )
                )

        await self._session.commit()

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
        return f"{path_id}:edge:{edge_index}"

    @staticmethod
    def _as_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
