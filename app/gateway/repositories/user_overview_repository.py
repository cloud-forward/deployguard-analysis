from __future__ import annotations

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.user_overview_repository import UserOverviewRepository
from app.gateway.models import AnalysisJob, AttackPath, Cluster, RemediationRecommendation, ScanRecord
from app.models.schemas import UserAssetListItemResponse, UserAssetListResponse, UserOverviewResponse


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

    async def list_assets(self, user_id: str) -> UserAssetListResponse:
        analysis_count_subquery = (
            select(func.count(AnalysisJob.id))
            .where(
                AnalysisJob.user_id == user_id,
                AnalysisJob.cluster_id == Cluster.id,
            )
            .scalar_subquery()
        )
        scan_count_subquery = (
            select(func.count(ScanRecord.id))
            .where(
                ScanRecord.user_id == user_id,
                ScanRecord.cluster_id == Cluster.id,
            )
            .scalar_subquery()
        )
        latest_analysis_status_subquery = (
            select(AnalysisJob.status)
            .where(
                AnalysisJob.user_id == user_id,
                AnalysisJob.cluster_id == Cluster.id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
            .scalar_subquery()
        )
        latest_scan_status_subquery = (
            select(ScanRecord.status)
            .where(
                ScanRecord.user_id == user_id,
                ScanRecord.cluster_id == Cluster.id,
            )
            .order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
            .limit(1)
            .scalar_subquery()
        )

        result = await self._session.execute(
            select(
                Cluster.id.label("cluster_id"),
                Cluster.name,
                Cluster.cluster_type,
                Cluster.aws_account_id,
                Cluster.aws_region,
                analysis_count_subquery.label("analysis_job_count"),
                scan_count_subquery.label("scan_record_count"),
                latest_analysis_status_subquery.label("latest_analysis_status"),
                latest_scan_status_subquery.label("latest_scan_status"),
            )
            .where(Cluster.user_id == user_id)
            .order_by(Cluster.created_at.desc(), Cluster.id.desc())
        )

        items = [
            UserAssetListItemResponse(
                cluster_id=row.cluster_id,
                name=row.name,
                cluster_type=row.cluster_type,
                aws_account_id=row.aws_account_id,
                aws_region=row.aws_region,
                analysis_job_count=int(row.analysis_job_count or 0),
                scan_record_count=int(row.scan_record_count or 0),
                latest_analysis_status=row.latest_analysis_status,
                latest_scan_status=row.latest_scan_status,
            )
            for row in result.all()
        ]
        return UserAssetListResponse(items=items, total=len(items))

    async def _scalar_count(self, stmt) -> int:
        value = await self._session.scalar(stmt)
        return int(value or 0)
