import uuid

import pytest
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.models import (
    AnalysisJob,
    AttackPath,
    AttackPathEdge,
    GraphSnapshot,
    RemediationRecommendation,
)
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository


@pytest.fixture
async def repo_and_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield SqlAlchemyAnalysisJobRepository(session), session

    await engine.dispose()


class TestSqlAlchemyAnalysisJobRepository:
    def test_analysis_job_graph_id_has_graph_snapshots_fk(self):
        foreign_keys = {fk.target_fullname for fk in AnalysisJob.__table__.c.graph_id.foreign_keys}
        assert foreign_keys == {"graph_snapshots.id"}

    def test_graph_snapshot_has_required_cluster_fk(self):
        foreign_keys = {fk.target_fullname for fk in GraphSnapshot.__table__.c.cluster_id.foreign_keys}
        assert foreign_keys == {"clusters.id"}
        assert GraphSnapshot.__table__.c.cluster_id.nullable is False

    def test_attack_path_edges_matches_real_schema_without_graph_id(self):
        columns = AttackPathEdge.__table__.c
        assert "graph_id" not in columns
        assert "sequence" in columns
        assert columns.path_id.nullable is False
        foreign_keys = {fk.target_fullname for fk in columns.path_id.foreign_keys}
        assert foreign_keys == {"attack_paths.id"}

    @pytest.mark.asyncio
    async def test_create_analysis_job_persists_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id_from_scan_record = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id_from_scan_record,
            k8s_scan_id="20260309T113020-k8s",
            aws_scan_id="20260309T113020-aws",
            image_scan_id="20260309T113020-image",
            expected_scans=["k8s", "aws", "image"],
        )

        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        assert job is not None
        assert job.cluster_id == cluster_id_from_scan_record
        assert job.status == "pending"
        assert job.expected_scans == ["k8s", "aws", "image"]

    @pytest.mark.asyncio
    async def test_create_analysis_job_rejects_non_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session

        with pytest.raises(ValueError):
            await repo.create_analysis_job(
                cluster_id="not-a-uuid",
                k8s_scan_id="20260309T113020-k8s",
                aws_scan_id="20260309T113020-aws",
                image_scan_id="20260309T113020-image",
                expected_scans=["k8s", "aws", "image"],
            )

        total = await session.scalar(select(func.count()).select_from(AnalysisJob))
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_analysis_job_returns_row_by_id(self, repo_and_session):
        repo, _ = repo_and_session
        job_id = await repo.create_analysis_job(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
            expected_scans=["k8s", "image"],
        )

        job = await repo.get_analysis_job(job_id)

        assert job is not None
        assert job.id == job_id
        assert job.k8s_scan_id == "k8s-1"

    @pytest.mark.asyncio
    async def test_list_analysis_jobs_filters_by_cluster_and_status(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        other_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

        pending_job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
            expected_scans=["k8s", "image"],
        )
        running_job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-2",
            aws_scan_id=None,
            image_scan_id="img-2",
            expected_scans=["k8s", "image"],
        )
        await repo.create_analysis_job(
            cluster_id=other_cluster_id,
            k8s_scan_id="k8s-3",
            aws_scan_id=None,
            image_scan_id="img-3",
            expected_scans=["k8s", "image"],
        )
        running_job = await session.get(AnalysisJob, running_job_id)
        running_job.status = "running"
        await session.commit()

        cluster_jobs = await repo.list_analysis_jobs(cluster_id=cluster_id)
        running_jobs = await repo.list_analysis_jobs(cluster_id=cluster_id, status="running")

        assert {job.id for job in cluster_jobs} == {pending_job_id, running_job_id}
        assert [job.id for job in running_jobs] == [running_job_id]

    @pytest.mark.asyncio
    async def test_persist_attack_paths_creates_graph_snapshot_links_job_and_stores_edges(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            expected_scans=["k8s", "aws", "image"],
        )

        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="k8s-1-graph",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[
                {
                    "path_id": "path:0:ingress:prod:web->s3:123:data",
                    "path": ["ingress:prod:web", "pod:prod:api", "s3:123:data"],
                    "raw_final_risk": 0.91,
                    "risk_score": 0.91,
                    "length": 3,
                    "edges": [
                        {"source": "ingress:prod:web", "target": "pod:prod:api", "type": "ingress_exposes_service"},
                        {"source": "pod:prod:api", "target": "s3:123:data", "type": "iam_role_access_resource"},
                    ],
                }
            ],
        )

        uuid.UUID(graph_id)

        snapshot = await session.get(GraphSnapshot, graph_id)
        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        path = await session.scalar(select(AttackPath).where(AttackPath.graph_id == graph_id))
        edge_rows = (
            await session.execute(
                select(AttackPathEdge)
                .where(AttackPathEdge.path_id == path.id)
                .order_by(AttackPathEdge.sequence)
            )
        ).scalars().all()

        assert snapshot is not None
        assert snapshot.cluster_id == cluster_id
        assert job is not None
        assert job.graph_id == graph_id
        assert path is not None
        assert path.path_id == "path:0:ingress:prod:web->s3:123:data"
        assert path.risk_level == "critical"
        assert path.entry_node_id == "ingress:prod:web"
        assert path.target_node_id == "s3:123:data"
        assert path.node_ids == ["ingress:prod:web", "pod:prod:api", "s3:123:data"]
        assert len(path.edge_ids) == 2
        assert [edge.id for edge in edge_rows] == path.edge_ids
        assert [edge.sequence for edge in edge_rows] == [0, 1]
        assert [edge.edge_type for edge in edge_rows] == [
            "ingress_exposes_service",
            "iam_role_access_resource",
        ]
        assert all(edge.path_id == path.id for edge in edge_rows)

    @pytest.mark.asyncio
    async def test_persist_remediation_recommendations_stores_ranked_rows_for_graph(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            expected_scans=["k8s", "aws", "image"],
        )

        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="k8s-1-graph",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[],
        )

        await repo.persist_remediation_recommendations(
            cluster_id=cluster_id,
            graph_id=graph_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            remediation_optimization={
                "summary": {"selected_count": 2},
                "recommendations": [
                    {
                        "id": "restrict_ingress:ingress:prod:web:service:prod:web:ingress_exposes_service",
                        "edge_source": "ingress:prod:web",
                        "edge_target": "service:prod:web",
                        "edge_type": "ingress_exposes_service",
                        "fix_type": "restrict_ingress",
                        "fix_description": "Restrict ingress exposure.",
                        "blocked_path_ids": ["path-a", "path-b"],
                        "blocked_path_indices": [0, 1],
                        "fix_cost": 1.0,
                        "edge_score": 1.5,
                        "covered_risk": 1.5,
                        "cumulative_risk_reduction": 1.5,
                        "metadata": {"edge_source_type": "ingress"},
                    },
                    {
                        "id": "remove_privileged:pod:prod:escape:node:worker-1:escapes_to",
                        "edge_source": "pod:prod:escape",
                        "edge_target": "node:worker-1",
                        "edge_type": "escapes_to",
                        "fix_type": "remove_privileged",
                        "fix_description": "Remove the privileged pod config.",
                        "blocked_path_ids": ["path-c"],
                        "blocked_path_indices": [2],
                        "fix_cost": 2.2,
                        "edge_score": 0.7,
                        "covered_risk": 0.7,
                        "cumulative_risk_reduction": 2.2,
                        "metadata": {"edge_source_type": "pod"},
                    },
                ],
            },
        )

        snapshot = await session.get(GraphSnapshot, graph_id)
        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        rows = (
            await session.execute(
                select(RemediationRecommendation)
                .where(RemediationRecommendation.graph_id == graph_id)
                .order_by(RemediationRecommendation.recommendation_rank)
            )
        ).scalars().all()

        assert snapshot is not None
        assert snapshot.cluster_id == cluster_id
        assert job is not None
        assert job.graph_id == graph_id
        assert [row.recommendation_rank for row in rows] == [0, 1]
        assert [row.fix_type for row in rows] == ["restrict_ingress", "remove_privileged"]
        assert rows[0].blocked_path_ids == ["path-a", "path-b"]
        assert rows[0].covered_risk == 1.5
        assert rows[0].cumulative_risk_reduction == 1.5
        assert rows[1].cumulative_risk_reduction == 2.2
