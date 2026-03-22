"""
Lightweight dependency providers for application services.
FastAPI can inject these into endpoints. API layer must not import gateways directly.
"""
from __future__ import annotations
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.analysis_service import AnalysisService
from app.application.services.attack_graph_service import AttackGraphService
from app.application.services.inventory_service import InventoryService
from app.config import settings
from app.gateway.db.session import get_db
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.application.services.scan_service import ScanService
from app.application.services.s3_service import S3Service
from app.application.services.cluster_service import ClusterService
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository


def get_analysis_service(
    db: AsyncSession = Depends(get_db),
) -> AnalysisService:
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    scan_repo = SQLAlchemyScanRepository(session=db)
    return AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo)

def get_scan_service(
    db: AsyncSession = Depends(get_db),
) -> ScanService:
    scan_repo = SQLAlchemyScanRepository(session=db)
    s3_service = S3Service(bucket_name=settings.S3_BUCKET_NAME, region=settings.AWS_REGION)
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    analysis_service = AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo)
    return ScanService(scan_repository=scan_repo, s3_service=s3_service, analysis_service=analysis_service)


def get_cluster_service(
    db: AsyncSession = Depends(get_db),
) -> ClusterService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    return ClusterService(cluster_repository=cluster_repo)


def get_attack_graph_service(
    db: AsyncSession = Depends(get_db),
) -> AttackGraphService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    return AttackGraphService(cluster_repository=cluster_repo, db=db)


def get_inventory_service(
    db: AsyncSession = Depends(get_db),
) -> InventoryService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    snapshot_repo = SQLAlchemyInventorySnapshotRepository(session=db)
    return InventoryService(cluster_repository=cluster_repo, inventory_snapshot_repository=snapshot_repo)


# ---------------------------------------------------------------------------
# 신규: Asset Inventory View Service (v1)
# 기존 get_inventory_service와 완전히 분리된 별도 provider
# ---------------------------------------------------------------------------

from app.application.services.inventory_view_service import InventoryViewService  # noqa: E402


def get_inventory_view_service(
    db: AsyncSession = Depends(get_db),
) -> InventoryViewService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    scan_repo = SQLAlchemyScanRepository(session=db)
    snapshot_repo = SQLAlchemyInventorySnapshotRepository(session=db)
    return InventoryViewService(
        cluster_repository=cluster_repo,
        scan_repository=scan_repo,
        snapshot_repository=snapshot_repo,
        db=db,  # graph_snapshots / graph_nodes / attack_paths 직접 쿼리용
    )
