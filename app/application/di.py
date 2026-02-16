"""
Lightweight dependency providers for application services.
FastAPI can inject these into endpoints. API layer must not import gateways directly.
"""
from __future__ import annotations
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.analysis_service import AnalysisService
from app.domain.repositories.analysis_jobs import RiskResultRepository
from app.gateway.db import get_db
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
# DISABLED: OpenSearch repository import commented out to allow app startup
# from app.gateway.repositories.risk_results_opensearch import OpenSearchRiskResultRepository


def get_analysis_service(
    db: AsyncSession = Depends(get_db),
) -> AnalysisService:
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    # DISABLED: OpenSearch repository temporarily disabled
    # risk_repo: RiskResultRepository | None = OpenSearchRiskResultRepository()  # client wired lazily
    risk_repo: RiskResultRepository | None = None  # Temporarily disabled - OpenSearch not available
    return AnalysisService(jobs_repo=jobs_repo, risk_repo=risk_repo)
