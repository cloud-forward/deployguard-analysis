"""
Integration tests for SQLAlchemyScanRepository using SQLite in-memory database.
"""
from datetime import datetime, timedelta
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.core.constants import SCAN_STATUS_FAILED

CLUSTER_1 = "11111111-1111-1111-1111-111111111111"
CLUSTER_2 = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as session:
        yield SQLAlchemyScanRepository(session)

    await engine.dispose()


class TestSQLAlchemyScanRepository:

    @pytest.mark.asyncio
    async def test_create_and_retrieve(self, repo):
        """Create a ScanRecord and retrieve by scan_id"""
        await repo.create(scan_id="test-001", cluster_id=CLUSTER_1, scanner_type="k8s")

        found = await repo.get_by_scan_id("test-001")
        assert found is not None
        assert found.scan_id == "test-001"
        assert found.cluster_id == CLUSTER_1

    @pytest.mark.asyncio
    async def test_create_persists_request_source_and_requested_at(self, repo):
        requested_at = datetime(2026, 3, 9, 12, 0, 0)

        await repo.create(
            scan_id="test-001b",
            cluster_id=CLUSTER_1,
            scanner_type="k8s",
            request_source="scheduled",
            requested_at=requested_at,
        )

        found = await repo.get_by_scan_id("test-001b")
        assert found.request_source == "scheduled"
        assert found.requested_at == requested_at

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, repo):
        """get_by_scan_id returns None for unknown scan_id"""
        found = await repo.get_by_scan_id("does-not-exist")
        assert found is None

    @pytest.mark.asyncio
    async def test_update_status(self, repo):
        """update_status changes the status field"""
        await repo.create(scan_id="test-002", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.update_status("test-002", "completed")

        found = await repo.get_by_scan_id("test-002")
        assert found.status == "completed"

    @pytest.mark.asyncio
    async def test_update_files(self, repo):
        """update_files stores S3 key list"""
        await repo.create(scan_id="test-003", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.update_files("test-003", ["scans/c1/test-003/k8s/k8s-snapshot.json"])

        found = await repo.get_by_scan_id("test-003")
        assert "scans/c1/test-003/k8s/k8s-snapshot.json" in found.s3_keys

    @pytest.mark.asyncio
    async def test_list_by_cluster(self, repo):
        """list_by_cluster returns only matching cluster's scans"""
        await repo.create(scan_id="s1", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.create(scan_id="s2", cluster_id=CLUSTER_1, scanner_type="aws")
        await repo.create(scan_id="s3", cluster_id=CLUSTER_2, scanner_type="k8s")

        results = await repo.list_by_cluster(CLUSTER_1)
        assert len(results) == 2
        assert all(r.cluster_id == CLUSTER_1 for r in results)

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_record(self, repo):
        """find_active_scan returns a record when an active scan exists"""
        await repo.create(scan_id="active-001", cluster_id=CLUSTER_1, scanner_type="k8s")

        found = await repo.find_active_scan(CLUSTER_1, "k8s")

        assert found is not None
        assert found.scan_id == "active-001"

    @pytest.mark.asyncio
    async def test_find_active_scan_uploading_status(self, repo):
        """find_active_scan returns a record with status=uploading"""
        await repo.create(scan_id="active-002", cluster_id=CLUSTER_1, scanner_type="aws")
        await repo.update_status("active-002", "uploading")

        found = await repo.find_active_scan(CLUSTER_1, "aws")

        assert found is not None
        assert found.status == "uploading"

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_completed(self, repo):
        """find_active_scan returns None when the only scan is completed"""
        await repo.create(scan_id="done-001", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.update_status("done-001", "completed")

        found = await repo.find_active_scan(CLUSTER_1, "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_failed(self, repo):
        """find_active_scan returns None when the only scan is failed"""
        await repo.create(scan_id="fail-001", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.update_status("fail-001", "failed")

        found = await repo.find_active_scan(CLUSTER_1, "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_update_status_with_completed_at(self, repo):
        """update_status persists completed_at when provided"""
        await repo.create(scan_id="test-004", cluster_id=CLUSTER_1, scanner_type="k8s")
        completed = datetime(2026, 3, 9, 12, 0, 0)

        await repo.update_status("test-004", "completed", completed_at=completed)

        found = await repo.get_by_scan_id("test-004")
        assert found.status == "completed"
        assert found.completed_at == completed

    @pytest.mark.asyncio
    async def test_list_active_scans_filters_to_active_statuses(self, repo):
        await repo.create(scan_id="active-003", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.create(scan_id="done-003", cluster_id=CLUSTER_1, scanner_type="aws")
        await repo.update_status("done-003", "completed")

        found = await repo.list_active_scans(CLUSTER_1)

        assert [record.scan_id for record in found] == ["active-003"]

    @pytest.mark.asyncio
    async def test_list_active_scans_can_filter_scanner_types(self, repo):
        await repo.create(scan_id="active-k8s", cluster_id=CLUSTER_1, scanner_type="k8s")
        await repo.create(scan_id="active-aws", cluster_id=CLUSTER_1, scanner_type="aws")

        found = await repo.list_active_scans(CLUSTER_1, scanner_types=["aws"])

        assert [record.scan_id for record in found] == ["active-aws"]

    @pytest.mark.asyncio
    async def test_mark_failed_sets_failed_status_and_completed_at(self, repo):
        completed_at = datetime(2026, 3, 9, 12, 5, 0)
        await repo.create(scan_id="fail-002", cluster_id=CLUSTER_1, scanner_type="k8s")

        await repo.mark_failed("fail-002", completed_at=completed_at)

        found = await repo.get_by_scan_id("fail-002")
        assert found.status == SCAN_STATUS_FAILED
        assert found.completed_at == completed_at

    @pytest.mark.asyncio
    async def test_claim_next_queued_scan(self, repo):
        await repo.create(scan_id="q-001", cluster_id=CLUSTER_1, scanner_type="k8s", status="created", request_source="manual")
        now = datetime(2026, 3, 9, 12, 0, 0)
        claimed = await repo.claim_next_queued_scan(
            cluster_id=CLUSTER_1,
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_expires_at=now + timedelta(seconds=300),
            started_at=now,
        )
        assert claimed is not None
        assert claimed.status == "processing"
        assert claimed.claimed_by == "worker-1"
        assert claimed.claimed_at == now
        assert claimed.started_at == now
        assert claimed.lease_expires_at == now + timedelta(seconds=300)

        found = await repo.get_by_scan_id("q-001")
        assert found.status == "processing"
        assert found.claimed_by == "worker-1"
        assert found.claimed_at == now
        assert found.started_at == now
        assert found.lease_expires_at == now + timedelta(seconds=300)

    @pytest.mark.asyncio
    async def test_claim_next_queued_scan_none_when_empty(self, repo):
        now = datetime(2026, 3, 9, 12, 0, 0)
        claimed = await repo.claim_next_queued_scan(
            cluster_id=CLUSTER_1,
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_expires_at=now + timedelta(seconds=300),
            started_at=now,
        )
        assert claimed is None
