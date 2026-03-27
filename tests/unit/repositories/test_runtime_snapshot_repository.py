from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.gateway.db.base import Base
from app.gateway.models import Cluster, RuntimeSnapshot
from app.gateway.repositories.runtime_snapshot_repository import SQLAlchemyRuntimeSnapshotRepository


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as session:
        session.add(Cluster(id="cluster-1", name="cluster-1", cluster_type="eks"))
        session.add(Cluster(id="cluster-2", name="cluster-2", cluster_type="eks"))
        await session.commit()
        yield SQLAlchemyRuntimeSnapshotRepository(session)

    await engine.dispose()


class TestSQLAlchemyRuntimeSnapshotRepository:
    @pytest.mark.asyncio
    async def test_create_and_get_by_s3_key(self, repo):
        uploaded_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        created = await repo.create(
            cluster_id="cluster-1",
            s3_key="runtime/cluster-1/20260327T120000Z/events.json",
            snapshot_at=uploaded_at,
            uploaded_at=uploaded_at,
            fact_count=0,
        )

        found = await repo.get_by_s3_key(created.s3_key)

        assert found is not None
        assert found.id == created.id
        assert found.fact_count == 0

    @pytest.mark.asyncio
    async def test_create_is_idempotent_by_unique_s3_key(self, repo):
        uploaded_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        first = await repo.create(
            cluster_id="cluster-1",
            s3_key="runtime/cluster-1/20260327T120000Z/events.json",
            snapshot_at=uploaded_at,
            uploaded_at=uploaded_at,
            fact_count=3,
        )

        second = await repo.create(
            cluster_id="cluster-1",
            s3_key="runtime/cluster-1/20260327T120000Z/events.json",
            snapshot_at=uploaded_at + timedelta(minutes=1),
            uploaded_at=uploaded_at + timedelta(minutes=1),
            fact_count=9,
        )

        assert second.id == first.id
        assert second.fact_count == 3

    @pytest.mark.asyncio
    async def test_get_latest_by_cluster_id_uses_uploaded_at_desc(self, repo):
        older = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        newer = older + timedelta(minutes=5)
        await repo.create(
            cluster_id="cluster-1",
            s3_key="runtime/cluster-1/20260327T120000Z/events.json",
            snapshot_at=older,
            uploaded_at=older,
            fact_count=1,
        )
        await repo.create(
            cluster_id="cluster-1",
            s3_key="runtime/cluster-1/20260327T120500Z/events.json",
            snapshot_at=newer,
            uploaded_at=newer,
            fact_count=2,
        )

        latest = await repo.get_latest_by_cluster_id("cluster-1")

        assert latest is not None
        assert latest.s3_key == "runtime/cluster-1/20260327T120500Z/events.json"
        assert latest.fact_count == 2
