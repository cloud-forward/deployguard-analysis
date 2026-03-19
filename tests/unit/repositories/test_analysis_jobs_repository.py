import pytest
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.models import AnalysisJob
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
