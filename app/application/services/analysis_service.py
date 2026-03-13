"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
from typing import Dict, Any

from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import AnalysisJobRepository


class AnalysisService:
    def __init__(
        self,
        jobs_repo: AnalysisJobRepository,
    ) -> None:
        self._jobs = jobs_repo

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        job_id = await self._jobs.create_job(request.target_id, _params_dict(request))
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis started for target {request.target_id}",
        )

    async def maybe_trigger_analysis(self, cluster_id: str) -> None:
        pass


def _params_dict(request: AnalysisRequest) -> Dict[str, Any]:
    return {"depth": request.depth, **(request.parameters or {})}
