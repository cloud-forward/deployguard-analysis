from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.gateway.db.base import Base
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield SQLAlchemyInventorySnapshotRepository(session)

    await engine.dispose()


class TestSQLAlchemyInventorySnapshotRepository:
    @pytest.mark.asyncio
    async def test_create_persists_snapshot_fields(self, repo):
        scanned_at = datetime(2026, 3, 19, 9, 30, tzinfo=timezone.utc)
        payload = {
            "iam_roles": [{"name": "role-a"}],
            "s3_buckets": [{"name": "bucket-a", "arn": "arn:aws:s3:::bucket-a"}],
        }

        created = await repo.create(
            cluster_id="c1",
            scan_id="scan-1",
            scanned_at=scanned_at,
            raw_result_json=payload,
        )

        latest = await repo.get_latest_by_cluster("c1")

        assert created.cluster_id == "c1"
        assert created.scan_id == "scan-1"
        assert created.scanned_at.replace(tzinfo=timezone.utc) == scanned_at
        assert latest is not None
        assert latest.raw_result_json == payload

    @pytest.mark.asyncio
    async def test_create_and_get_latest_by_cluster(self, repo):
        await repo.create(
            cluster_id="c1",
            scan_id="scan-1",
            scanned_at=datetime(2026, 3, 19, 10, 0, tzinfo=timezone.utc),
            raw_result_json={"s3_buckets": [{"name": "bucket-a"}]},
        )
        await repo.create(
            cluster_id="c1",
            scan_id="scan-2",
            scanned_at=datetime(2026, 3, 19, 11, 0, tzinfo=timezone.utc),
            raw_result_json={"s3_buckets": [{"name": "bucket-b"}]},
        )

        latest = await repo.get_latest_by_cluster("c1")

        assert latest is not None
        assert latest.scan_id == "scan-2"
        assert latest.raw_result_json["s3_buckets"][0]["name"] == "bucket-b"

    @pytest.mark.asyncio
    async def test_get_latest_by_cluster_returns_none_when_missing(self, repo):
        latest = await repo.get_latest_by_cluster("missing-cluster")

        assert latest is None

    @pytest.mark.asyncio
    async def test_latest_snapshot_payload_can_be_used_for_asset_lookup(self, repo):
        await repo.create(
            cluster_id="c1",
            scan_id="scan-1",
            scanned_at=datetime(2026, 3, 19, 10, 0, tzinfo=timezone.utc),
            raw_result_json={
                "iam_roles": [{"name": "role-old"}],
                "s3_buckets": [],
            },
        )
        await repo.create(
            cluster_id="c1",
            scan_id="scan-2",
            scanned_at=datetime(2026, 3, 19, 11, 0, tzinfo=timezone.utc),
            raw_result_json={
                "iam_roles": [{"name": "role-new"}],
                "s3_buckets": [{"name": "bucket-a", "arn": "arn:aws:s3:::bucket-a"}],
            },
        )

        latest = await repo.get_latest_by_cluster("c1")

        assert latest is not None
        assert latest.scan_id == "scan-2"
        assert latest.raw_result_json["iam_roles"][0]["name"] == "role-new"
        assert latest.raw_result_json["s3_buckets"][0]["arn"] == "arn:aws:s3:::bucket-a"

    @pytest.mark.asyncio
    async def test_list_latest_returns_latest_snapshot_per_cluster(self, repo):
        await repo.create(
            cluster_id="c1",
            scan_id="scan-1",
            scanned_at=datetime(2026, 3, 19, 10, 0, tzinfo=timezone.utc),
            raw_result_json={},
        )
        await repo.create(
            cluster_id="c1",
            scan_id="scan-2",
            scanned_at=datetime(2026, 3, 19, 11, 0, tzinfo=timezone.utc),
            raw_result_json={},
        )
        await repo.create(
            cluster_id="c2",
            scan_id="scan-3",
            scanned_at=datetime(2026, 3, 19, 12, 0, tzinfo=timezone.utc),
            raw_result_json={},
        )

        latest = await repo.list_latest()

        assert {snapshot.scan_id for snapshot in latest} == {"scan-2", "scan-3"}

    @pytest.mark.asyncio
    async def test_list_latest_returns_empty_when_no_snapshots_exist(self, repo):
        latest = await repo.list_latest()

        assert latest == []
