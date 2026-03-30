"""
Lightweight dependency providers for application services.
FastAPI can inject these into endpoints. API layer must not import gateways directly.
"""
from __future__ import annotations
import logging
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.analysis_service import AnalysisService
from app.application.services.auth_service import AuthService
from app.application.services.attack_graph_service import AttackGraphService
from app.application.services.inventory_service import InventoryService
from app.application.services.llm_provider_config_service import LLMProviderConfigService
from app.application.services.recommendation_explanation_service import RecommendationExplanationService
from app.application.llm.providers.openai_explanation_client import OpenAIExplanationClient
from app.application.llm.providers.xai_explanation_client import XAIExplanationClient
from app.config import settings
from app.gateway.db.session import get_db
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
from app.gateway.repositories.llm_provider_config_repository import SQLAlchemyLLMProviderConfigRepository
from app.gateway.repositories.user_repository import SQLAlchemyUserRepository
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.application.services.scan_service import ScanService
from app.application.services.s3_service import S3Service
from app.application.services.cluster_service import ClusterService
from app.application.services.runtime_snapshot_service import RuntimeSnapshotService
from app.application.services.user_overview_service import UserOverviewService
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.gateway.repositories.runtime_snapshot_repository import SQLAlchemyRuntimeSnapshotRepository
from app.gateway.repositories.user_overview_repository import SQLAlchemyUserOverviewRepository

logger = logging.getLogger(__name__)


def get_auth_service(
    db: AsyncSession = Depends(get_db),
) -> AuthService:
    user_repo = SQLAlchemyUserRepository(session=db)
    return AuthService(user_repository=user_repo)


def get_analysis_service(
    db: AsyncSession = Depends(get_db),
) -> AnalysisService:
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    scan_repo = SQLAlchemyScanRepository(session=db)
    s3_service = S3Service(bucket_name=settings.S3_BUCKET_NAME, region=settings.AWS_REGION)
    return AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo, s3_service=s3_service, db=db)

def get_scan_service(
    db: AsyncSession = Depends(get_db),
) -> ScanService:
    scan_repo = SQLAlchemyScanRepository(session=db)
    s3_service = S3Service(bucket_name=settings.S3_BUCKET_NAME, region=settings.AWS_REGION)
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    analysis_service = AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo, s3_service=s3_service, db=db)
    return ScanService(
        scan_repository=scan_repo,
        s3_service=s3_service,
        analysis_service=analysis_service,
        cluster_repository=cluster_repo,
    )


def get_cluster_service(
    db: AsyncSession = Depends(get_db),
) -> ClusterService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    return ClusterService(cluster_repository=cluster_repo)


def get_runtime_snapshot_service(
    db: AsyncSession = Depends(get_db),
) -> RuntimeSnapshotService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    runtime_repo = SQLAlchemyRuntimeSnapshotRepository(session=db)
    runtime_s3_service = S3Service(bucket_name=settings.S3_RUNTIME_BUCKET_NAME, region=settings.AWS_REGION)
    return RuntimeSnapshotService(
        runtime_snapshot_repository=runtime_repo,
        cluster_repository=cluster_repo,
        s3_service=runtime_s3_service,
    )


def get_attack_graph_service(
    db: AsyncSession = Depends(get_db),
) -> AttackGraphService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    return AttackGraphService(cluster_repository=cluster_repo, db=db)


def get_recommendation_explanation_service(
    db: AsyncSession = Depends(get_db),
) -> RecommendationExplanationService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    attack_graph_service = AttackGraphService(cluster_repository=cluster_repo, db=db)
    config_repo = SQLAlchemyLLMProviderConfigRepository(session=db)
    jobs_repo = SqlAlchemyAnalysisJobRepository(session=db)
    providers = {
        "openai": OpenAIExplanationClient(),
        "xai": XAIExplanationClient(),
    }
    logger.debug(
        "remediation_explanation_service_constructed",
        extra={
            "provider_count": len(providers),
            "provider_names": sorted(providers.keys()),
        },
    )
    return RecommendationExplanationService(
        attack_graph_service=attack_graph_service,
        provider_config_repository=config_repo,
        analysis_jobs_repository=jobs_repo,
        providers=providers,
    )


def get_llm_provider_config_service(
    db: AsyncSession = Depends(get_db),
) -> LLMProviderConfigService:
    config_repo = SQLAlchemyLLMProviderConfigRepository(session=db)
    return LLMProviderConfigService(provider_config_repository=config_repo)


def get_inventory_service(
    db: AsyncSession = Depends(get_db),
) -> InventoryService:
    cluster_repo = SQLAlchemyClusterRepository(session=db)
    snapshot_repo = SQLAlchemyInventorySnapshotRepository(session=db)
    return InventoryService(cluster_repository=cluster_repo, inventory_snapshot_repository=snapshot_repo)


def get_user_overview_service(
    db: AsyncSession = Depends(get_db),
) -> UserOverviewService:
    overview_repo = SQLAlchemyUserOverviewRepository(session=db)
    return UserOverviewService(overview_repository=overview_repo)


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
