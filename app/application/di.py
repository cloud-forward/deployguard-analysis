"""
Lightweight dependency providers for application services.
FastAPI can inject these into endpoints. API layer must not import gateways directly.
"""
from __future__ import annotations
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.analysis_service import AnalysisService
from app.config import settings
from app.gateway.db.session import get_db
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.application.services.scan_service import ScanService
from app.application.services.s3_service import S3Service
from app.application.services.cluster_service import ClusterService
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository


def get_analysis_service(
    db: AsyncSession = Depends(get_db),
) -> AnalysisService:
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    return AnalysisService(jobs_repo=jobs_repo)


def get_scan_service(
    db: AsyncSession = Depends(get_db),
) -> ScanService:
    scan_repo = SQLAlchemyScanRepository(session=db)
    s3_service = S3Service(bucket_name=settings.S3_BUCKET_NAME, region=settings.AWS_REGION)
    return ScanService(scan_repository=scan_repo, s3_service=s3_service)


def get_cluster_service(
    db: AsyncSession = Depends(get_db),
) -> ClusterService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    return ClusterService(cluster_repository=cluster_repo)
