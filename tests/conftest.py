"""
Test configuration and fixtures for integration tests.
"""
from __future__ import annotations

import os
from datetime import datetime
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("S3_BUCKET_NAME", "test-bucket")

import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster
from app.main import app
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService
from app.core.constants import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STATUS_CREATED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PROCESSING,
    canonical_scan_file_name,
)
from app.models.schemas import ClusterResponse


class FakeScanRepository:
    """In-memory scan repository that matches the calling conventions in ScanService."""

    def __init__(self):
        self._store: dict = {}

    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        status: str = SCAN_STATUS_CREATED,
        request_source: str = "manual",
        requested_at=None,
    ):
        from datetime import datetime
        record = _FakeScanRecord(
            scan_id=scan_id,
            cluster_id=cluster_id,
            scanner_type=scanner_type,
            status=status,
            s3_keys=[],
            created_at=datetime.utcnow(),
            completed_at=None,
            request_source=request_source,
            requested_at=requested_at or datetime.utcnow(),
        )
        self._store[scan_id] = record
        return record

    async def get_by_scan_id(self, scan_id: str):
        return self._store.get(scan_id)

    async def update_status(self, scan_id: str, status: str, **kwargs):
        record = self._store.get(scan_id)
        if record:
            record.status = status
            if "completed_at" in kwargs:
                record.completed_at = kwargs["completed_at"]
        return record

    async def update(self, scan_id: str, status: str, s3_keys: list, completed_at=None):
        record = self._store.get(scan_id)
        if record:
            record.status = status
            record.s3_keys = s3_keys
            record.completed_at = completed_at
        return record

    async def update_files(self, scan_id: str, s3_keys: list):
        record = self._store.get(scan_id)
        if record:
            record.s3_keys = s3_keys
        return record

    async def list_by_cluster(self, cluster_id: str):
        return [r for r in self._store.values() if r.cluster_id == cluster_id]

    async def find_active_scan(self, cluster_id: str, scanner_type: str):
        for r in self._store.values():
            if r.cluster_id == cluster_id and r.scanner_type == scanner_type and r.status in ACTIVE_SCAN_STATUSES:
                return r
        return None

    async def list_active_scans(self, cluster_id: str, scanner_types: list[str] | None = None):
        records = [
            r for r in self._store.values()
            if r.cluster_id == cluster_id and r.status in ACTIVE_SCAN_STATUSES
        ]
        if scanner_types is not None:
            records = [r for r in records if r.scanner_type in scanner_types]
        return records

    async def mark_failed(self, scan_id: str, completed_at=None):
        record = self._store.get(scan_id)
        if record:
            record.status = SCAN_STATUS_FAILED
            record.completed_at = completed_at
        return record

    async def claim_next_queued_scan(self, cluster_id: str, scanner_type: str, claimed_by: str, lease_expires_at, started_at):
        queued = [
            r for r in self._store.values()
            if r.cluster_id == cluster_id and r.scanner_type == scanner_type and r.status == SCAN_STATUS_CREATED
        ]
        if not queued:
            return None
        queued.sort(key=lambda r: r.requested_at)
        record = queued[0]
        record.status = SCAN_STATUS_PROCESSING
        record.claimed_by = claimed_by
        record.claimed_at = started_at
        record.started_at = started_at
        record.lease_expires_at = lease_expires_at
        return record


class _FakeScanRecord:
    def __init__(self, scan_id, cluster_id, scanner_type, status, s3_keys, created_at, completed_at, request_source, requested_at):
        self.scan_id = scan_id
        self.cluster_id = cluster_id
        self.scanner_type = scanner_type
        self.status = status
        self.s3_keys = s3_keys
        self.created_at = created_at
        self.completed_at = completed_at
        self.request_source = request_source
        self.requested_at = requested_at


class FakeS3Service:
    """Mock S3 service that returns fake presigned URLs without making real AWS calls."""

    def generate_presigned_upload_url(
        self, cluster_id: str, scan_id: str, scanner_type: str, file_name: str, expires_in: int = 600
    ) -> tuple[str, str]:
        s3_key = f"scans/{cluster_id}/{scan_id}/{scanner_type}/{canonical_scan_file_name(scanner_type)}"
        fake_url = f"https://fake-s3.example.com/{s3_key}?X-Amz-Expires={expires_in}"
        return fake_url, s3_key

    def verify_file_exists(self, s3_key: str) -> bool:
        return True


class FakeClusterRepository:
    async def get_by_id(self, cluster_id: str):
        if cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890":
            return ClusterResponse(
                id=cluster_id,
                name="test-cluster",
                description=None,
                cluster_type="eks",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        if cluster_id == "b2c3d4e5-f6a7-8901-bcde-f12345678901":
            return ClusterResponse(
                id=cluster_id,
                name="aws-cluster",
                description=None,
                cluster_type="aws",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        return None


@pytest.fixture
def client():
    """
    FastAPI TestClient with overridden dependencies:
    - FakeScanRepository (in-memory, no DB required)
    - FakeS3Service (no real AWS calls)
    """
    fake_repo = FakeScanRepository()
    fake_s3 = FakeS3Service()
    fake_clusters = FakeClusterRepository()
    fake_service = ScanService(scan_repository=fake_repo, s3_service=fake_s3, cluster_repository=fake_clusters)  # noqa

    app.dependency_overrides[get_scan_service] = lambda: fake_service
    async def _fake_auth_cluster():
        return ClusterResponse(
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster

    with TestClient(app) as c:
        c.app_state["repo"] = fake_repo
        yield c

    app.dependency_overrides.clear()
