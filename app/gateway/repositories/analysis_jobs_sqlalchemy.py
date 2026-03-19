"""
SQLAlchemy implementation of AnalysisJobRepository.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.gateway.models import AnalysisJob


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
