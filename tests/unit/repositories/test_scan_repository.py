"""
Integration tests for SQLAlchemyScanRepository using SQLite in-memory database.
"""
import logging
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository


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
        await repo.create(scan_id="test-001", cluster_id="c1", scanner_type="k8s")

        found = await repo.get_by_scan_id("test-001")
        assert found is not None
        assert found.scan_id == "test-001"
        assert found.cluster_id == "c1"

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, repo):
        """get_by_scan_id returns None for unknown scan_id"""
        found = await repo.get_by_scan_id("does-not-exist")
        assert found is None

    @pytest.mark.asyncio
    async def test_update_status(self, repo):
        """update_status changes the status field"""
        await repo.create(scan_id="test-002", cluster_id="c1", scanner_type="k8s")
        await repo.update_status("test-002", "completed")

        found = await repo.get_by_scan_id("test-002")
        assert found.status == "completed"

    @pytest.mark.asyncio
    async def test_update_files(self, repo):
        """update_files stores S3 key list"""
        await repo.create(scan_id="test-003", cluster_id="c1", scanner_type="k8s")
        await repo.update_files("test-003", ["scans/c1/test-003/k8s.json"])

        found = await repo.get_by_scan_id("test-003")
        assert "scans/c1/test-003/k8s.json" in found.s3_keys

    @pytest.mark.asyncio
    async def test_list_by_cluster(self, repo):
        """list_by_cluster returns only matching cluster's scans"""
        await repo.create(scan_id="s1", cluster_id="c1", scanner_type="k8s")
        await repo.create(scan_id="s2", cluster_id="c1", scanner_type="aws")
        await repo.create(scan_id="s3", cluster_id="c2", scanner_type="k8s")

        results = await repo.list_by_cluster("c1")
        assert len(results) == 2
        assert all(r.cluster_id == "c1" for r in results)

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_record(self, repo):
        """find_active_scan returns a record when an active scan exists"""
        await repo.create(scan_id="active-001", cluster_id="c1", scanner_type="k8s")

        found = await repo.find_active_scan("c1", "k8s")

        assert found is not None
        assert found.scan_id == "active-001"

    @pytest.mark.asyncio
    async def test_find_active_scan_uploading_status(self, repo):
        """find_active_scan returns a record with status=uploading"""
        await repo.create(scan_id="active-002", cluster_id="c1", scanner_type="aws")
        await repo.update_status("active-002", "uploading")

        found = await repo.find_active_scan("c1", "aws")

        assert found is not None
        assert found.status == "uploading"

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_completed(self, repo):
        """find_active_scan returns None when the only scan is completed"""
        await repo.create(scan_id="done-001", cluster_id="c1", scanner_type="k8s")
        await repo.update_status("done-001", "completed")

        found = await repo.find_active_scan("c1", "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_failed(self, repo):
        """find_active_scan returns None when the only scan is failed"""
        await repo.create(scan_id="fail-001", cluster_id="c1", scanner_type="k8s")
        await repo.update_status("fail-001", "failed")

        found = await repo.find_active_scan("c1", "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_update_status_with_completed_at(self, repo):
        """update_status persists completed_at when provided"""
        from datetime import datetime
        await repo.create(scan_id="test-004", cluster_id="c1", scanner_type="k8s")
        completed = datetime(2026, 3, 9, 12, 0, 0)

        await repo.update_status("test-004", "completed", completed_at=completed)

        found = await repo.get_by_scan_id("test-004")
        assert found.status == "completed"
        assert found.completed_at == completed

    @pytest.mark.asyncio
    async def test_claim_next_queued_scan(self, repo):
        from datetime import datetime, timedelta
        await repo.create(scan_id="q-001", cluster_id="c1", scanner_type="k8s", status="queued", request_source="manual")
        now = datetime(2026, 3, 9, 12, 0, 0)
        claimed = await repo.claim_next_queued_scan(
            cluster_id="c1",
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_expires_at=now + timedelta(seconds=300),
            started_at=now,
        )
        assert claimed is not None
        assert claimed.status == "running"
        assert claimed.claimed_by == "worker-1"

    @pytest.mark.asyncio
    async def test_claim_next_queued_scan_none_when_empty(self, repo):
        from datetime import datetime, timedelta
        now = datetime(2026, 3, 9, 12, 0, 0)
        claimed = await repo.claim_next_queued_scan(
            cluster_id="c1",
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_expires_at=now + timedelta(seconds=300),
            started_at=now,
        )
        assert claimed is None

    @pytest.mark.asyncio
    async def test_create_duplicate_scan_id_logs_integrity_error(self, repo, caplog):
        await repo.create(scan_id="dup-001", cluster_id="c1", scanner_type="k8s")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(IntegrityError):
                await repo.create(scan_id="dup-001", cluster_id="c1", scanner_type="k8s")

        record = next(record for record in caplog.records if record.getMessage() == "scan.repository.integrity_error")
        assert record.operation == "create"
        assert record.scan_id == "dup-001"
        assert record.cluster_id == "c1"
        assert record.scanner_type == "k8s"
        assert record.error_type == "IntegrityError"
        assert record.exc_info is not None
