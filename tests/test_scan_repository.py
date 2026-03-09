"""
Integration tests for SQLAlchemyScanRepository using SQLite in-memory database.
"""
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.models.db_models import ScanRecord
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
        await repo.create(ScanRecord(
            scan_id="test-001", cluster_id="c1",
            scanner_type="k8s", status="created"
        ))

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
        await repo.create(ScanRecord(
            scan_id="test-002", cluster_id="c1",
            scanner_type="k8s", status="created"
        ))

        await repo.update_status("test-002", "processing")

        found = await repo.get_by_scan_id("test-002")
        assert found.status == "processing"

    @pytest.mark.asyncio
    async def test_update_files(self, repo):
        """update_files stores S3 key list"""
        await repo.create(ScanRecord(
            scan_id="test-003", cluster_id="c1",
            scanner_type="k8s", status="uploading"
        ))

        await repo.update_files("test-003", ["scans/c1/test-003/k8s.json"])

        found = await repo.get_by_scan_id("test-003")
        assert "scans/c1/test-003/k8s.json" in found.s3_keys

    @pytest.mark.asyncio
    async def test_list_by_cluster(self, repo):
        """list_by_cluster returns only matching cluster's scans"""
        await repo.create(ScanRecord(scan_id="s1", cluster_id="c1", scanner_type="k8s", status="created"))
        await repo.create(ScanRecord(scan_id="s2", cluster_id="c1", scanner_type="aws", status="created"))
        await repo.create(ScanRecord(scan_id="s3", cluster_id="c2", scanner_type="k8s", status="created"))

        results = await repo.list_by_cluster("c1")
        assert len(results) == 2
        assert all(r.cluster_id == "c1" for r in results)

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_record(self, repo):
        """find_active_scan returns a record when an active scan exists"""
        await repo.create(ScanRecord(
            scan_id="active-001", cluster_id="c1", scanner_type="k8s", status="created"
        ))

        found = await repo.find_active_scan("c1", "k8s")

        assert found is not None
        assert found.scan_id == "active-001"

    @pytest.mark.asyncio
    async def test_find_active_scan_uploading_status(self, repo):
        """find_active_scan returns a record with status=uploading"""
        await repo.create(ScanRecord(
            scan_id="active-002", cluster_id="c1", scanner_type="aws", status="uploading"
        ))

        found = await repo.find_active_scan("c1", "aws")

        assert found is not None
        assert found.status == "uploading"

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_completed(self, repo):
        """find_active_scan returns None when the only scan is completed"""
        await repo.create(ScanRecord(
            scan_id="done-001", cluster_id="c1", scanner_type="k8s", status="completed"
        ))

        found = await repo.find_active_scan("c1", "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_find_active_scan_returns_none_for_failed(self, repo):
        """find_active_scan returns None when the only scan is failed"""
        await repo.create(ScanRecord(
            scan_id="fail-001", cluster_id="c1", scanner_type="k8s", status="failed"
        ))

        found = await repo.find_active_scan("c1", "k8s")

        assert found is None

    @pytest.mark.asyncio
    async def test_update_status_with_completed_at(self, repo):
        """update_status persists completed_at when provided"""
        from datetime import datetime
        await repo.create(ScanRecord(
            scan_id="test-004", cluster_id="c1", scanner_type="k8s", status="processing"
        ))
        completed = datetime(2026, 3, 9, 12, 0, 0)

        await repo.update_status("test-004", "completed", completed_at=completed)

        found = await repo.get_by_scan_id("test-004")
        assert found.status == "completed"
        assert found.completed_at == completed
