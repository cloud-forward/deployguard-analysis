"""
SQLAlchemy implementation of AnalysisJobRepository.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.analysis_jobs import AnalysisJobRepository


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
