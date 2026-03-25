"""
Integration tests for scan ingestion API endpoints.

Uses FastAPI TestClient with:
- In-memory FakeScanRepository (no real DB)
- Configurable FakeS3Service (no real AWS calls)
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from dataclasses import dataclass
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster
from app.application.di import get_auth_service, get_scan_service
from app.application.services.auth_service import AuthService
from app.application.services.scan_service import ScanService
from app.config import settings
from app.core.constants import ACTIVE_SCAN_STATUSES, SCAN_STATUS_FAILED, canonical_scan_file_name
from app.main import app
from app.models.schemas import ClusterResponse
from app.security.passwords import hash_password

AUTH_CLUSTER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
OTHER_CLUSTER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    is_active: bool = True


class FakeUserRepository:
    def __init__(self, users: list[FakeUser]):
        self._by_email = {user.email: user for user in users}
        self._by_id = {user.id: user for user in users}

    async def get_by_email(self, email: str):
        return self._by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._by_id.get(user_id)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeScanRecord:
    def __init__(self, scan_id, cluster_id, scanner_type, user_id, status, s3_keys, created_at, completed_at, request_source, requested_at):
        self.scan_id = scan_id
        self.cluster_id = cluster_id
        self.scanner_type = scanner_type
        self.user_id = user_id
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
        user_id: str | None = None,
        status: str = "created",
        request_source: str = "manual",
        requested_at=None,
    ):
        from datetime import datetime
        record = _FakeScanRecord(
            scan_id=scan_id,
            cluster_id=cluster_id,
            scanner_type=scanner_type,
            user_id=user_id,
            status=status,
            s3_keys=[],
            created_at=datetime.utcnow(),
            completed_at=None,
            request_source=request_source,
            requested_at=requested_at or datetime.utcnow(),
        )
        self._store[scan_id] = record
        return record

    async def get_by_scan_id(self, scan_id: str, user_id: str | None = None):
        record = self._store.get(scan_id)
        if record is None:
            return None
        if user_id is not None and record.user_id != user_id:
            return None
        return record

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

    async def list_by_cluster(self, cluster_id: str, user_id: str | None = None):
        records = [r for r in self._store.values() if r.cluster_id == cluster_id]
        if user_id is not None:
            records = [r for r in records if r.user_id == user_id]
        return records

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
        s3_key = f"scans/{cluster_id}/{scan_id}/{scanner_type}/{canonical_scan_file_name(scanner_type)}"
        fake_url = f"https://fake-s3.example.com/{s3_key}?X-Amz-Expires={expires_in}"
        return fake_url, s3_key

    def verify_file_exists(self, s3_key: str) -> bool:
        return self.file_exists


class FakeClusterRepository:
    def __init__(self):
        self._clusters = {
            AUTH_CLUSTER_ID: ClusterResponse(
                id=AUTH_CLUSTER_ID,
                name="test-cluster",
                description=None,
                cluster_type="eks",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
            OTHER_CLUSTER_ID: ClusterResponse(
                id=OTHER_CLUSTER_ID,
                name="aws-cluster",
                description=None,
                cluster_type="aws",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
        }

    async def get_by_id(self, cluster_id: str):
        return self._clusters.get(cluster_id)


def _claim(client, scanner_type="k8s", claimed_by="worker-1", lease_seconds=300):
    return client.get(
        "/api/v1/scans/pending",
        params={
            "scanner_type": scanner_type,
            "claimed_by": claimed_by,
            "lease_seconds": lease_seconds,
        },
    )


def _auth_headers(client: TestClient, user_id: str = "user-1") -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _scan_id_for(response, scanner_type: str) -> str:
    scans = response.json()["scans"]
    match = next(scan for scan in scans if scan["scanner_type"] == scanner_type)
    return match["scan_id"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_client(file_exists: bool = True) -> TestClient:
    """Build a TestClient with fresh in-memory fakes."""
    fake_repo = FakeScanRepository()
    fake_s3 = FakeS3Service(file_exists=file_exists)
    fake_clusters = FakeClusterRepository()
    fake_service = ScanService(scan_repository=fake_repo, s3_service=fake_s3, cluster_repository=fake_clusters)
    app.dependency_overrides[get_scan_service] = lambda: fake_service
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_auth_service] = lambda: auth_service
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
    client = TestClient(app)
    client.app_state["repo"] = fake_repo
    return client


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
        user_id="user-1",
        status="completed",
        s3_keys=[],
        created_at=datetime(2026, 3, 9, 12, 0, 0),
        completed_at=datetime(2026, 3, 9, 12, 5, 0),
        request_source="manual",
        requested_at=datetime(2026, 3, 9, 11, 59, 0),
    )
    fake_clusters = FakeClusterRepository()
    fake_service = ScanService(scan_repository=fake_repo, s3_service=fake_s3, cluster_repository=fake_clusters)
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
        """Returns 201 with fan-out scan list and status=created."""
        response = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": AUTH_CLUSTER_ID,
        })
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "created"
        assert [scan["scanner_type"] for scan in data["scans"]] == ["k8s", "image"]

    def test_start_scan_id_format(self, client):
        """k8s fan-out scan_id must match YYYYMMDDTHHmmSS-{scanner_type}."""
        response = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": AUTH_CLUSTER_ID,
        })
        scan_id = _scan_id_for(response, "k8s")
        assert re.match(r"^\d{8}T\d{6}-k8s$", scan_id), (
            f"scan_id '{scan_id}' does not match expected format"
        )

    def test_start_scan_duplicate_returns_409(self, client):
        """Second start for same cluster fan-out returns 409 when a target scanner is already active."""
        payload = {"cluster_id": AUTH_CLUSTER_ID}
        first = client.post("/api/v1/scans/start", headers=_auth_headers(client), json=payload)
        assert first.status_code == 201

        second = client.post("/api/v1/scans/start", headers=_auth_headers(client), json=payload)
        assert second.status_code == 409

    def test_start_scan_allows_new_after_completed(self, client):
        """A new cluster-level scan is allowed once all fan-out scans are completed."""
        payload = {"cluster_id": AUTH_CLUSTER_ID}
        start_resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json=payload)
        for scanner_type in ("k8s", "image"):
            scan_id = _scan_id_for(start_resp, scanner_type)
            claim_resp = _claim(client, scanner_type=scanner_type)
            assert claim_resp.status_code == 200
            url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": f"{scanner_type}.json"})
            s3_key = url_resp.json()["s3_key"]
            client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
            status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
            assert status_resp.json()["status"] == "completed"

        new_resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})
        assert new_resp.status_code == 201

    def test_stale_created_scan_no_longer_blocks_future_start(self, client):
        first = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": OTHER_CLUSTER_ID})
        scan_id = _scan_id_for(first, "aws")
        record = client.app_state["repo"]._store.pop(scan_id)
        record.scan_id = "20000101T000010-aws"
        record.requested_at = datetime.utcnow() - timedelta(
            seconds=settings.SCAN_CREATED_STALE_SECONDS + 5
        )
        client.app_state["repo"]._store[record.scan_id] = record

        second = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": OTHER_CLUSTER_ID})

        assert second.status_code == 201
        assert client.app_state["repo"]._store["20000101T000010-aws"].status == "failed"

    def test_start_scan_missing_fields(self, client):
        """Missing required fields returns 422."""
        response = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={})
        assert response.status_code == 422

    def test_start_scan_fan_out_differs_by_cluster_type(self, client):
        """eks cluster creates k8s+image, aws cluster creates aws."""
        r1 = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})
        r2 = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": OTHER_CLUSTER_ID})
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert [scan["scanner_type"] for scan in r1.json()["scans"]] == ["k8s", "image"]
        assert [scan["scanner_type"] for scan in r2.json()["scans"]] == ["aws"]

    def test_start_scan_persists_authenticated_user_id(self, client):
        response = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})

        assert response.status_code == 201
        assert {record.user_id for record in client.app_state["repo"]._store.values()} == {"user-1"}


# ---------------------------------------------------------------------------
# POST /api/scans/{scan_id}/upload-url
# ---------------------------------------------------------------------------

class TestUploadUrl:

    def _start(self, client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s") -> str:
        resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": cluster_id
        })
        return _scan_id_for(resp, scanner_type)

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
        """s3_key must follow scans/{cluster_id}/{scan_id}/{scanner_type}/{scanner_type}-snapshot.json."""
        scan_id = self._start(client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s")
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        response = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "data.json"})
        s3_key = response.json()["s3_key"]
        assert s3_key == f"scans/{AUTH_CLUSTER_ID}/{scan_id}/k8s/k8s-snapshot.json"

    def test_upload_url_transitions_status_to_uploading(self, client):
        """After calling upload-url, scan status becomes 'uploading'."""
        scan_id = self._start(client)
        claim_resp = _claim(client)
        assert claim_resp.status_code == 200
        client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"})
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
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
        start = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": cluster_id
        })
        scan_id = _scan_id_for(start, scanner_type)
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
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
        assert status_resp.json()["status"] == "completed"

    def test_complete_scan_missing_file_returns_400(self, client_missing_s3):
        """Returns 400 when a file is not found in S3."""
        scan_id, s3_key = self._start_and_get_key(client_missing_s3)
        response = client_missing_s3.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        assert response.status_code == 400


class TestManualFail:

    def _start_and_get_key(self, client, cluster_id=AUTH_CLUSTER_ID, scanner_type="k8s") -> tuple[str, str]:
        start = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": cluster_id
        })
        scan_id = _scan_id_for(start, scanner_type)
        claim_resp = _claim(client, scanner_type=scanner_type)
        assert claim_resp.status_code == 200
        url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"})
        s3_key = url_resp.json()["s3_key"]
        return scan_id, s3_key

    def test_manual_fail_created_scan(self, client):
        start = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})
        scan_id = _scan_id_for(start, "k8s")

        response = client.post(f"/api/v1/scans/{scan_id}/fail")

        assert response.status_code == 202
        assert response.json()["status"] == "failed"

    def test_manual_fail_terminal_scan_is_idempotent(self, client):
        start = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})
        scan_id = _scan_id_for(start, "k8s")
        _claim(client)
        s3_key = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "scan.json"}).json()["s3_key"]
        client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})

        response = client.post(f"/api/v1/scans/{scan_id}/fail")

        assert response.status_code == 202
        assert response.json()["status"] == "completed"

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
        start_resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": AUTH_CLUSTER_ID
        })
        scan_id = _scan_id_for(start_resp, "k8s")

        response = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["cluster_id"] == AUTH_CLUSTER_ID
        assert data["scanner_type"] == "k8s"
        assert data["status"] == "created"
        assert "created_at" in data

    def test_get_status_not_found(self, client):
        """Unknown scan_id returns 404."""
        response = client.get("/api/v1/scans/nonexistent/status", headers=_auth_headers(client))
        assert response.status_code == 404

    def test_status_transitions_created_processing_uploading_completed(self, client):
        """Validates full status transition: created → processing → uploading → completed."""
        start_resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={
            "cluster_id": AUTH_CLUSTER_ID
        })
        scan_id = _scan_id_for(start_resp, "image")

        # created
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == "created"

        claim_resp = _claim(client, scanner_type="image")
        assert claim_resp.status_code == 200

        # processing
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == "processing"

        # uploading
        url_resp = client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": "cve.json"})
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == "uploading"

        # completed
        s3_key = url_resp.json()["s3_key"]
        client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": [s3_key]})
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == "completed"

    def test_get_status_not_visible_to_other_user(self, client):
        start_resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={"cluster_id": AUTH_CLUSTER_ID})
        scan_id = _scan_id_for(start_resp, "k8s")

        response = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client, "user-2"))

        assert response.status_code == 404
