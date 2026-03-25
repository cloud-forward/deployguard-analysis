from __future__ import annotations

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.user_overview_repository import UserOverviewRepository
from app.gateway.models import AnalysisJob, AttackPath, Cluster, RemediationRecommendation, ScanRecord
from app.models.schemas import UserOverviewResponse


class SQLAlchemyUserOverviewRepository(UserOverviewRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get_overview(self, user_id: str) -> UserOverviewResponse:
        cluster_type_counts = await self._session.execute(
            select(Cluster.cluster_type, func.count(Cluster.id))
            .where(Cluster.user_id == user_id)
            .group_by(Cluster.cluster_type)
        )
        cluster_counts = {cluster_type: count for cluster_type, count in cluster_type_counts.all()}

        total_clusters = sum(cluster_counts.values())
        total_analysis_jobs = await self._scalar_count(
            select(func.count(AnalysisJob.id)).where(AnalysisJob.user_id == user_id)
        )
        total_scan_records = await self._scalar_count(
            select(func.count(ScanRecord.id)).where(ScanRecord.user_id == user_id)
        )

        owned_graph_ids = (
            select(distinct(AnalysisJob.graph_id).label("graph_id"))
            .where(
                AnalysisJob.user_id == user_id,
                AnalysisJob.graph_id.is_not(None),
            )
            .subquery()
        )

        total_attack_paths = await self._scalar_count(
            select(func.count(AttackPath.id)).where(AttackPath.graph_id.in_(select(owned_graph_ids.c.graph_id)))
        )
        total_remediation_recommendations = await self._scalar_count(
            select(func.count(RemediationRecommendation.id)).where(
                RemediationRecommendation.graph_id.in_(select(owned_graph_ids.c.graph_id))
            )
        )

        return UserOverviewResponse(
            total_clusters=total_clusters,
            eks_clusters=cluster_counts.get("eks", 0),
            self_managed_clusters=cluster_counts.get("self-managed", 0),
            aws_clusters=cluster_counts.get("aws", 0),
            total_analysis_jobs=total_analysis_jobs,
            total_scan_records=total_scan_records,
            total_attack_paths=total_attack_paths,
            total_remediation_recommendations=total_remediation_recommendations,
        )

    async def _scalar_count(self, stmt) -> int:
        value = await self._session.scalar(stmt)
        return int(value or 0)
