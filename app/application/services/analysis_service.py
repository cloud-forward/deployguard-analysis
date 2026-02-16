"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
from typing import Dict, Any

from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import (
    AnalysisJobRepository,
    RiskResultRepository,
)


class AnalysisService:
    def __init__(
        self,
        jobs_repo: AnalysisJobRepository,
        risk_repo: RiskResultRepository | None = None,
    ) -> None:
        self._jobs = jobs_repo
        self._risk = risk_repo

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        # 1) Create job
        job_id = await self._jobs.create_job(request.target_id, _params_dict(request))

        # 2) TODO: Build graph and run algorithms (GraphBuilder, PathFinder, RiskEngine)
        # 3) TODO: Persist results via repositories (risk_repo)

        # 4) Return response DTO
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis started for target {request.target_id}",
        )


def _params_dict(request: AnalysisRequest) -> Dict[str, Any]:
    return {"depth": request.depth, **(request.parameters or {})}
