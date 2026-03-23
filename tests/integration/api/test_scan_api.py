"""
Integration tests for scan ingestion API endpoints.

Uses FastAPI TestClient with:
- In-memory FakeScanRepository (no real DB)
- Configurable FakeS3Service (no real AWS calls)
"""
from __future__ import annotations

import re
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster
from app.main import app
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService
from app.core.constants import ACTIVE_SCAN_STATUSES
from app.models.schemas import ClusterResponse

AUTH_CLUSTER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
OTHER_CLUSTER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

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


class FakeScanRepository:
    """In-memory scan repository."""

    def __init__(self):
        self._store: dict = {}

    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        status: str = "created",
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

    async def claim_next_queued_scan(self, cluster_id: str, scanner_type: str, claimed_by: str, lease_expires_at, started_at):
        queued = [
            r for r in self._store.values()
            if r.cluster_id == cluster_id and r.scanner_type == scanner_type and r.status == "created"
        ]
        if not queued:
            return None
        queued.sort(key=lambda r: r.requested_at)
        record = queued[0]
        record.status = "processing"
        record.claimed_by = claimed_by
        record.claimed_at = started_at
        record.started_at = started_at
        record.lease_expires_at = lease_expires_at
        return record


class FakeS3Service:
    """Mock S3 service. Set `file_exists` to False to simulate missing files."""

    def __init__(self, file_exists: bool = True):
        self.file_exists = file_exists

    def generate_presigned_upload_url(
        self, cluster_id: str, scan_id: str, scanner_type: str, file_name: str, expires_in: int = 600
    ) -> tuple[str, str]:
        s3_key = f"scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}"
        fake_url = f"https://fake-s3.example.com/{s3_key}?X-Amz-Expires={expires_in}"
        return fake_url, s3_key

    def verify_file_exists(self, s3_key: str) -> bool:
        return self.file_exists


def _claim(client, scanner_type="k8s", claimed_by="worker-1", lease_seconds=300):
    return client.get(
        "/api/v1/scans/pending",
        params={
            "scanner_type": scanner_type,
            "claimed_by": claimed_by,
            "lease_seconds": lease_seconds,
        },
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_client(file_exists: bool = True) -> TestClient:
    """Build a TestClient with fresh in-memory fakes."""
    fake_repo = FakeScanRepository()
    fake_s3 = FakeS3Service(file_exists=file_exists)
    fake_service = ScanService(scan_repository=fake_repo, s3_service=fake_s3)
    app.dependency_overrides[get_scan_service] = lambda: fake_service
    async def _fake_auth_cluster():
        return ClusterResponse(
            id=AUTH_CLUSTER_ID,
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    return TestClient(app)


@pytest.fixture
def client():
    """TestClient with S3 that reports all files as existing."""
    c = make_client(file_exists=True)
    with c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_missing_s3():
    """TestClient with S3 that reports all files as missing."""
    c = make_client(file_exists=False)
    with c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_with_completed_scan():
    """TestClient pre-seeded with a scan record in 'completed' status."""
    from datetime import datetime
    fake_repo = FakeScanRepository()
    fake_s3 = FakeS3Service(file_exists=True)
    scan_id = "20260309T120000-k8s"
    fake_repo._store[scan_id] = _FakeScanRecord(
        scan_id=scan_id,
        cluster_id="c1",
        scanner_type="k8s",
        status="completed",
        s3_keys=[],
        created_at=datetime(2026, 3, 9, 12, 0, 0),
        completed_at=datetime(2026, 3, 9, 12, 5, 0),
        request_source="manual",
        requested_at=datetime(2026, 3, 9, 11, 59, 0),
    )
    fake_service = ScanService(scan_repository=fake_repo, s3_service=fake_s3)
    app.dependency_overrides[get_scan_service] = lambda: fake_service
    async def _fake_auth_cluster():
        return ClusterResponse(
            id=AUTH_CLUSTER_ID,
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        c._completed_scan_id = scan_id
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/scans/start
# ---------------------------------------------------------------------------

class TestStartScan:

    def test_start_scan_success(self, client):
        """Returns 201 with scan_id and status=created."""
        response = client.post("/api/v1/scans/start", json={
            "cluster_id": AUTH_CLUSTER_ID,
            "scanner_type": "k8s",
        })
        assert response.status_code == 201
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "created"

    def test_start_scan_id_format(self, client):
        """scan_id must match YYYYMMDDTHHmmSS-{scanner_type}."""
        response = client.post("/api/v1/scans/start", json={
            "cluster_id": AUTH_CLUSTER_ID,
            "scanner_type": "k8s",
        })
        scan_id = response.json()["scan_id"]
        assert re.match(r"^\d{8}T\d{6}-k8s$", scan_id), (
            f"scan_id '{scan_id}' does not match expected format"
        )

    def test_start_scan_duplicate_returns_409(self, client):
        """Second start for same cluster+scanner_type returns 409."""
        payload = {"cluster_id": AUTH_CLUSTER_ID, "scanner_type": "k8s"}
        first = client.post("/api/v1/scans/start", json=payload)
        assert first.status_code == 201

        second = client.post("/api/v1/scans/start", json=payload)
        assert second.status_code == 409

    def test_start_scan_allows_new_after_completed(self, client):
        """A new scan is allowed once the previous one is completed."""
        payload = {"cluster_id": AUTH_CLUSTER_ID, "scanner_type": "aws"}
        start_resp = client.post("/api/v1/scans/start", json=payload)
        scan_id = start_resp.json()["scan_id"]

        # Drive the scan to completed state via the API
        claim_resp = _claim(client, scanner_type="aws")
        assert claim_resp.status_code == 200
        url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "aws.json"})
        s3_key = url_resp.json()["s3_key"]
        client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})

        # Verify the scan lifecycle is complete and no longer considered active.
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status")
        assert status_resp.json()["status"] == "completed"

        # A new scan for a different cluster should always succeed
        new_resp = client.post("/api/v1/scans/start", json={
            "cluster_id": OTHER_CLUSTER_ID, "scanner_type": "aws"
        })
        assert new_resp.status_code == 201

    def test_start_scan_invalid_scanner_type(self, client):
        """Invalid scanner_type returns 422."""
        response = client.post("/api/v1/scans/start", json={
            "cluster_id": AUTH_CLUSTER_ID,
            "scanner_type": "invalid",
        })
        assert response.status_code == 422

    def test_start_scan_missing_fields(self, client):
        """Missing required fields returns 422."""
        response = client.post("/api/v1/scans/start", json={})
        assert response.status_code == 422

    def test_start_scan_different_scanner_types_allowed(self, client):
        """Same cluster with different scanner_type is allowed concurrently."""
        r1 = client.post("/api/v1/scans/start", json={"cluster_id": AUTH_CLUSTER_ID, "scanner_type": "k8s"})
        r2 = client.post("/api/v1/scans/start", json={"cluster_id": AUTH_CLUSTER_ID, "scanner_type": "aws"})
        assert r1.status_code == 201
        assert r2.status_code == 201


# ---------------------------------------------------------------------------
# POST /api/scans/{scan_id}/upload-url
# ---------------------------------------------------------------------------

class TestUploadUrl:

    def _start(self, client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s") -> str:
        resp = client.post("/api/v1/scans/start", json={
            "cluster_id": cluster_id, "scanner_type": scanner_type
        })
        return resp.json()["scan_id"]

    def test_upload_url_success(self, client):
        """Returns 200 with upload_url, s3_key, and expires_in."""
        scan_id = self._start(client)
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        response = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"})
        assert response.status_code == 200
        data = response.json()
        assert "upload_url" in data
        assert "s3_key" in data
        assert data["expires_in"] == 600

    def test_upload_url_s3_key_format(self, client):
        """s3_key must follow scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}."""
        scan_id = self._start(client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s")
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        response = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "data.json"})
        s3_key = response.json()["s3_key"]
        assert s3_key == f"scans/{AUTH_CLUSTER_ID}/{scan_id}/k8s/data.json"

    def test_upload_url_transitions_status_to_uploading(self, client):
        """After calling upload-url, scan status becomes 'uploading'."""
        scan_id = self._start(client)
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"})
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status")
        assert status_resp.json()["status"] == "uploading"

    def test_upload_url_scan_not_found(self, client):
        """Unknown scan_id returns 404."""
        response = client.post("/api/v1/scans/nonexistent/upload-url", json={"file_name": "scan.json"})
        assert response.status_code == 404

    def test_upload_url_non_json_file_rejected(self, client):
        """Non-JSON file name returns 422."""
        scan_id = self._start(client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s")
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        response = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.txt"})
        assert response.status_code == 422

    def test_upload_url_completed_scan_returns_409(self, client_with_completed_scan):
        """Requesting upload URL for a scan in 'completed' status returns 409."""
        scan_id = client_with_completed_scan._completed_scan_id
        response = client_with_completed_scan.post(
            f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan2.json"}
        )
        assert response.status_code == 409


# ---------------------------------------------------------------------------
# POST /api/scans/{scan_id}/complete
# ---------------------------------------------------------------------------

class TestCompleteScan:

    def _start_and_get_key(self, client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s") -> tuple[str, str]:
        start = client.post("/api/v1/scans/start", json={
            "cluster_id": cluster_id, "scanner_type": scanner_type
        })
        scan_id = start.json()["scan_id"]
        claim_resp = _claim(client, scanner_type=scanner_type)
        assert claim_resp.status_code == 200
        url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"})
        s3_key = url_resp.json()["s3_key"]
        return scan_id, s3_key

    def test_complete_scan_success(self, client):
        """Returns 202 with status=accepted."""
        scan_id, s3_key = self._start_and_get_key(client)
        response = client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "completed"
        assert data["scan_id"] == scan_id

    def test_complete_scan_transitions_to_completed(self, client):
        """After complete, scan status becomes 'completed'."""
        scan_id, s3_key = self._start_and_get_key(client)
        client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status")
        assert status_resp.json()["status"] == "completed"

    def test_complete_scan_missing_file_returns_400(self, client_missing_s3):
        """Returns 400 when a file is not found in S3."""
        scan_id, s3_key = self._start_and_get_key(client_missing_s3)
        response = client_missing_s3.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        assert response.status_code == 400

    def test_complete_scan_empty_files_rejected(self, client):
        """Empty files list returns 422 (schema validation)."""
        scan_id, s3_key = self._start_and_get_key(client)
        response = client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": []})
        assert response.status_code == 422

    def test_complete_scan_not_found_returns_404(self, client):
        """Unknown scan_id returns 404."""
        response = client.post("/api/v1/scans/nonexistent/complete", json={"files": ["some/file.json"]})
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/status
# ---------------------------------------------------------------------------

class TestScanStatus:

    def test_get_status_success(self, client):
        """Returns 200 with full scan metadata."""
        start_resp = client.post("/api/v1/scans/start", json={
            "cluster_id": AUTH_CLUSTER_ID, "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.get(f"/api/v1/scans/{scan_id}/status")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["cluster_id"] == AUTH_CLUSTER_ID
        assert data["scanner_type"] == "k8s"
        assert data["status"] == "created"
        assert "created_at" in data

    def test_get_status_not_found(self, client):
        """Unknown scan_id returns 404."""
        response = client.get("/api/v1/scans/nonexistent/status")
        assert response.status_code == 404

    def test_status_transitions_created_processing_uploading_completed(self, client):
        """Validates full status transition: created → processing → uploading → completed."""
        start_resp = client.post("/api/v1/scans/start", json={
            "cluster_id": AUTH_CLUSTER_ID, "scanner_type": "image"
        })
        scan_id = start_resp.json()["scan_id"]

        # created
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == "created"

        claim_resp = _claim(client, scanner_type="image")
        assert claim_resp.status_code == 200

        # processing
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == "processing"

        # uploading
        url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "cve.json"})
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == "uploading"

        # completed
        s3_key = url_resp.json()["s3_key"]
        client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == "completed"
