import pytest
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.models import AnalysisJob, AttackPath, AttackPathEdge, GraphSnapshot
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

    @pytest.mark.asyncio
    async def test_create_analysis_job_persists_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id_from_scan_record = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id_from_scan_record,
            k8s_scan_id="20260309T113020-k8s",
            aws_scan_id="20260309T113020-aws",
            image_scan_id="20260309T113020-image",
        )

        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        assert job is not None
        assert job.cluster_id == cluster_id_from_scan_record
        assert job.status == "pending"

    @pytest.mark.asyncio
    async def test_create_analysis_job_rejects_non_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session

        with pytest.raises(ValueError):
            await repo.create_analysis_job(
                cluster_id="not-a-uuid",
                k8s_scan_id="20260309T113020-k8s",
                aws_scan_id="20260309T113020-aws",
                image_scan_id="20260309T113020-image",
            )

        total = await session.scalar(select(func.count()).select_from(AnalysisJob))
        assert total == 0

    @pytest.mark.asyncio
    async def test_persist_attack_paths_creates_graph_snapshot_links_job_and_stores_edges(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        graph_id = "k8s-1-graph"
        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
        )

        await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id=graph_id,
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

        snapshot = await session.get(GraphSnapshot, graph_id)
        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        path = await session.scalar(select(AttackPath).where(AttackPath.graph_id == graph_id))
        edge_rows = (
            await session.execute(
                select(AttackPathEdge)
                .where(AttackPathEdge.graph_id == graph_id)
                .order_by(AttackPathEdge.edge_index)
            )
        ).scalars().all()

        assert snapshot is not None
        assert job is not None
        assert job.graph_id == graph_id
        assert path is not None
        assert path.path_id == "path:0:ingress:prod:web->s3:123:data"
        assert path.risk_level == "critical"
        assert path.entry_node_id == "ingress:prod:web"
        assert path.target_node_id == "s3:123:data"
        assert path.node_ids == ["ingress:prod:web", "pod:prod:api", "s3:123:data"]
        assert path.edge_ids == [
            "path:0:ingress:prod:web->s3:123:data:edge:0",
            "path:0:ingress:prod:web->s3:123:data:edge:1",
        ]
        assert [edge.edge_index for edge in edge_rows] == [0, 1]
        assert [edge.edge_type for edge in edge_rows] == [
            "ingress_exposes_service",
            "iam_role_access_resource",
        ]
