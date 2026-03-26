from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster
from app.application.di import get_auth_service
from app.application.services.auth_service import AuthService
from app.application.services.analysis_service import AnalysisService
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService
from app.config import settings
from app.core.constants import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_CREATED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PROCESSING,
    SCAN_STATUS_UPLOADING,
    canonical_scan_file_name,
)
from app.main import app
from app.models.schemas import ClusterResponse
from app.security.passwords import hash_password


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    is_active: bool = True
    name: str = ""


class FakeUserRepository:
    def __init__(self, users: list[FakeUser]):
        self._by_email = {user.email: user for user in users}
        self._by_id = {user.id: user for user in users}

    async def get_by_email(self, email: str):
        return self._by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._by_id.get(user_id)


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
    def __init__(self):
        self._store: dict = {}

    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        user_id: str | None = None,
        status: str = SCAN_STATUS_CREATED,
        request_source: str = "manual",
        requested_at=None,
    ):
        if scan_id in self._store:
            raise ValueError(f"Duplicate scan_id: {scan_id}")
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

    async def update_status(self, scan_id: str, status: str, user_id: str | None = None, **kwargs):
        record = self._store.get(scan_id)
        if record and user_id is not None and record.user_id != user_id:
            return None
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

    async def mark_failed(self, scan_id: str, completed_at=None, user_id: str | None = None):
        record = self._store.get(scan_id)
        if record and user_id is not None and record.user_id != user_id:
            return None
        if record:
            record.status = SCAN_STATUS_FAILED
            record.completed_at = completed_at
        return record

    async def get_latest_completed_scans(self, cluster_id: str):
        completed = {}
        for record in self._store.values():
            if record.cluster_id != cluster_id or record.status != SCAN_STATUS_COMPLETED:
                continue
            existing = completed.get(record.scanner_type)
            if existing is None or record.created_at >= existing.created_at:
                completed[record.scanner_type] = record
        return completed

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


class FakeS3Service:
    def generate_presigned_upload_url(self, cluster_id, scan_id, scanner_type, file_name, expires_in=600):
        s3_key = f"scans/{cluster_id}/{scan_id}/{scanner_type}/{canonical_scan_file_name(scanner_type)}"
        return f"https://fake-s3.example.com/{s3_key}", s3_key

    def generate_presigned_download_url(self, s3_key: str, expires_in: int = 600) -> str:
        return f"https://fake-s3.example.com/{s3_key}?download=1&X-Amz-Expires={expires_in}"

    def verify_file_exists(self, s3_key: str) -> bool:
        return True


class FakeS3ServiceMissingFile(FakeS3Service):
    def verify_file_exists(self, s3_key: str) -> bool:
        return False


class FakeClusterRepository:
    def __init__(self):
        self._clusters = {
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890": ClusterResponse(
                id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                name="test-cluster",
                description=None,
                cluster_type="eks",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
            "b2c3d4e5-f6a7-8901-bcde-f12345678901": ClusterResponse(
                id="b2c3d4e5-f6a7-8901-bcde-f12345678901",
                name="aws-cluster",
                description=None,
                cluster_type="aws",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
        }

    async def get_by_id(self, cluster_id: str):
        return self._clusters.get(cluster_id)


class FakeAnalysisJobRepository:
    def __init__(self):
        self.jobs = []

    async def create_job(self, target_id: str, params: dict) -> str:
        return "job_stub"

    async def create_analysis_job(self, cluster_id: str, k8s_scan_id: str, aws_scan_id: str, image_scan_id: str) -> str:
        self.jobs.append(
            {
                "cluster_id": cluster_id,
                "k8s_scan_id": k8s_scan_id,
                "aws_scan_id": aws_scan_id,
                "image_scan_id": image_scan_id,
                "status": "pending",
            }
        )
        return "analysis-job"


@pytest.fixture
def client():
    repo = FakeScanRepository()
    s3 = FakeS3Service()
    clusters = FakeClusterRepository()
    service = ScanService(scan_repository=repo, s3_service=s3, cluster_repository=clusters)
    app.dependency_overrides[get_scan_service] = lambda: service
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
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_with_repo():
    repo = FakeScanRepository()
    s3 = FakeS3Service()
    clusters = FakeClusterRepository()
    service = ScanService(scan_repository=repo, s3_service=s3, cluster_repository=clusters)
    app.dependency_overrides[get_scan_service] = lambda: service
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
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        yield c, repo
    app.dependency_overrides.clear()


@pytest.fixture
def client_missing_s3():
    repo = FakeScanRepository()
    s3 = FakeS3ServiceMissingFile()
    clusters = FakeClusterRepository()
    service = ScanService(scan_repository=repo, s3_service=s3, cluster_repository=clusters)
    app.dependency_overrides[get_scan_service] = lambda: service
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
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_missing_s3_with_repo():
    repo = FakeScanRepository()
    s3 = FakeS3ServiceMissingFile()
    clusters = FakeClusterRepository()
    service = ScanService(scan_repository=repo, s3_service=s3, cluster_repository=clusters)
    app.dependency_overrides[get_scan_service] = lambda: service
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
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        yield c, repo
    app.dependency_overrides.clear()


@pytest.fixture
def client_with_analysis_repo():
    repo = FakeScanRepository()
    s3 = FakeS3Service()
    clusters = FakeClusterRepository()
    jobs_repo = FakeAnalysisJobRepository()
    analysis = AnalysisService(jobs_repo=jobs_repo, scan_repo=repo)
    service = ScanService(scan_repository=repo, s3_service=s3, analysis_service=analysis, cluster_repository=clusters)
    app.dependency_overrides[get_scan_service] = lambda: service
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
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            name="test-cluster",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    with TestClient(app) as c:
        yield c, repo, jobs_repo
    app.dependency_overrides.clear()


def _auth_headers(client: TestClient, user_id: str = "user-1") -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _start(
    client,
    cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    request_source="manual",
):
    return client.post(
        "/api/v1/scans/start",
        headers=_auth_headers(client),
        json={"cluster_id": cluster_id, "request_source": request_source},
    )


def _scan_id_for(response, scanner_type: str) -> str:
    scans = response.json()["scans"]
    match = next(scan for scan in scans if scan["scanner_type"] == scanner_type)
    return match["scan_id"]


def _upload_url(client, scan_id, file_name="scan.json"):
    return client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": file_name})


def _claim(
    client,
    scanner_type="k8s",
    claimed_by=None,
    lease_seconds=300,
):
    params = {
        "scanner_type": scanner_type,
        "lease_seconds": lease_seconds,
    }
    if claimed_by is not None:
        params["claimed_by"] = claimed_by
    return client.get(
        "/api/v1/scans/pending",
        params=params,
    )


def _complete(client, scan_id, files=None):
    if files is None:
        resp = _upload_url(client, scan_id)
        files = [resp.json()["s3_key"]]
    return client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": files})


def _scan_log_records(caplog):
    logger_names = {
        "app.api.scan",
        "app.application.services.scan_service",
        "app.application.services.analysis_service",
    }
    return [record for record in caplog.records if record.name in logger_names and record.getMessage().startswith("scan.")]


class TestScanStart:
    def test_stale_created_scan_auto_failed_before_new_start(self, client_with_repo):
        client, repo = client_with_repo
        start = _start(client)
        scan_id = _scan_id_for(start, "k8s")
        image_scan_id = _scan_id_for(start, "image")
        image_record = repo._store.pop(image_scan_id)
        image_record.scan_id = "20000101T000000-image"
        image_record.status = SCAN_STATUS_FAILED
        repo._store[image_record.scan_id] = image_record
        record = repo._store.pop(scan_id)
        record.scan_id = "20000101T000000-k8s"
        record.requested_at = datetime.utcnow() - timedelta(
            seconds=settings.SCAN_CREATED_STALE_SECONDS + 5
        )
        repo._store[record.scan_id] = record

        resp = _start(client)

        assert resp.status_code == 201
        assert repo._store["20000101T000000-k8s"].status == SCAN_STATUS_FAILED

    def test_stale_processing_scan_auto_failed_before_new_start(self, client_with_repo):
        client, repo = client_with_repo
        start = _start(client)
        scan_id = _scan_id_for(start, "k8s")
        image_scan_id = _scan_id_for(start, "image")
        image_record = repo._store.pop(image_scan_id)
        image_record.scan_id = "20000101T000001-image"
        image_record.status = SCAN_STATUS_FAILED
        repo._store[image_record.scan_id] = image_record
        _claim(client, scanner_type="k8s")
        record = repo._store.pop(scan_id)
        record.scan_id = "20000101T000001-k8s"
        record.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        repo._store[record.scan_id] = record

        resp = _start(client)

        assert resp.status_code == 201
        assert repo._store["20000101T000001-k8s"].status == SCAN_STATUS_FAILED

    def test_stale_uploading_scan_auto_failed_before_new_start(self, client_with_repo):
        client, repo = client_with_repo
        start = _start(client)
        scan_id = _scan_id_for(start, "k8s")
        image_scan_id = _scan_id_for(start, "image")
        image_record = repo._store.pop(image_scan_id)
        image_record.scan_id = "20000101T000002-image"
        image_record.status = SCAN_STATUS_FAILED
        repo._store[image_record.scan_id] = image_record
        _claim(client, scanner_type="k8s")
        repo._store[scan_id].status = SCAN_STATUS_UPLOADING
        record = repo._store.pop(scan_id)
        record.scan_id = "20000101T000002-k8s"
        record.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        repo._store[record.scan_id] = record

        resp = _start(client)

        assert resp.status_code == 201
        assert repo._store["20000101T000002-k8s"].status == SCAN_STATUS_FAILED

    def test_terminal_scans_ignored_by_auto_cleanup(self, client_with_repo):
        client, repo = client_with_repo
        completed_scan_id = "completed-aws"
        failed_scan_id = "failed-aws"
        repo._store[completed_scan_id] = _FakeScanRecord(
            scan_id=completed_scan_id,
            cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901",
            scanner_type="aws",
            user_id="user-1",
            status=SCAN_STATUS_COMPLETED,
            s3_keys=[],
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            request_source="manual",
            requested_at=datetime.utcnow(),
        )
        repo._store[failed_scan_id] = _FakeScanRecord(
            scan_id=failed_scan_id,
            cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901",
            scanner_type="aws",
            user_id="user-1",
            status=SCAN_STATUS_FAILED,
            s3_keys=[],
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            request_source="manual",
            requested_at=datetime.utcnow(),
        )

        resp = _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901")

        assert resp.status_code == 201
        assert repo._store[completed_scan_id].status == SCAN_STATUS_COMPLETED
        assert repo._store[failed_scan_id].status == SCAN_STATUS_FAILED

    def test_k8s_cluster_creates_k8s_and_image_scan_records(self, client):
        resp = _start(client)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == SCAN_STATUS_CREATED
        assert [scan["scanner_type"] for scan in data["scans"]] == ["k8s", "image"]

    def test_aws_cluster_creates_only_aws_scan_record(self, client):
        resp = _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901")
        assert resp.status_code == 201
        data = resp.json()
        assert [scan["scanner_type"] for scan in data["scans"]] == ["aws"]

    def test_scan_ids_contain_scanner_types(self, client):
        resp = _start(client)
        data = resp.json()
        assert "k8s" in _scan_id_for(resp, "k8s")
        assert "image" in _scan_id_for(resp, "image")

    def test_manual_request_source_accepted(self, client):
        resp = _start(client, request_source="manual")
        assert resp.status_code == 201

    def test_scheduled_request_source_accepted(self, client):
        resp = _start(client, request_source="scheduled")
        assert resp.status_code == 201

    def test_omitted_request_source_uses_valid_default(self, client):
        resp = client.post(
            "/api/v1/scans/start",
            headers=_auth_headers(client),
            json={
                "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            },
        )
        assert resp.status_code == 201

    def test_start_scan_persists_authenticated_user_id(self, client_with_repo):
        client, repo = client_with_repo

        resp = _start(client)

        assert resp.status_code == 201
        records = list(repo._store.values())
        assert len(records) == 2
        assert {record.user_id for record in records} == {"user-1"}

    def test_invalid_request_source_rejected(self, client):
        resp = _start(client, request_source="api")
        assert resp.status_code == 422

    def test_invalid_request_source_does_not_create_record(self, client_with_repo):
        client, repo = client_with_repo
        resp = _start(client, request_source="api")
        assert resp.status_code == 422
        assert repo._store == {}

    def test_missing_cluster_id_rejected(self, client):
        resp = client.post("/api/v1/scans/start", headers=_auth_headers(client), json={})
        assert resp.status_code == 422

    def test_duplicate_active_scan_rejected(self, client):
        _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        resp = _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert resp.status_code == 409

    def test_different_cluster_types_fan_out_differently(self, client):
        assert _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890").status_code == 201
        assert _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901").status_code == 201

    def test_same_scanner_type_different_clusters_allowed(self, client):
        r1 = _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        r2 = _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901")
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert _scan_id_for(r1, "k8s") != _scan_id_for(r2, "aws")

    def test_scan_start_with_unknown_cluster_returns_404(self, client):
        resp = _start(client, cluster_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
        assert resp.status_code == 404

    def test_start_emits_lifecycle_logs(self, client, caplog):
        with caplog.at_level(logging.INFO):
            resp = client.post(
                "/api/v1/scans/start",
                headers={**_auth_headers(client), "X-Request-ID": "req-start-1"},
                json={
                    "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "request_source": "manual",
                },
            )

        assert resp.status_code == 201
        records = _scan_log_records(caplog)
        events = [record.getMessage() for record in records]
        assert "scan.start.request_received" in events
        assert "scan.start.record_created" in events

        request_received = next(record for record in records if record.getMessage() == "scan.start.request_received")
        assert request_received.request_id == "req-start-1"
        assert request_received.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert request_received.request_source == "manual"

        created_records = [record for record in records if record.getMessage() == "scan.start.record_created"]
        assert len(created_records) == 2
        assert {record.scanner_type for record in created_records} == {"k8s", "image"}

    def test_stale_cleanup_emits_auto_fail_log(self, client_with_repo, caplog):
        client, repo = client_with_repo
        start = _start(client)
        scan_id = _scan_id_for(start, "k8s")
        image_scan_id = _scan_id_for(start, "image")
        image_record = repo._store.pop(image_scan_id)
        image_record.scan_id = "20000101T000003-image"
        image_record.status = SCAN_STATUS_FAILED
        repo._store[image_record.scan_id] = image_record
        record = repo._store.pop(scan_id)
        record.scan_id = "20000101T000003-k8s"
        record.requested_at = datetime.utcnow() - timedelta(
            seconds=settings.SCAN_CREATED_STALE_SECONDS + 5
        )
        repo._store[record.scan_id] = record

        with caplog.at_level(logging.WARNING):
            resp = client.post(
                "/api/v1/scans/start",
                headers={**_auth_headers(client), "X-Request-ID": "req-stale-1"},
                json={
                    "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "request_source": "manual",
                },
            )

        assert resp.status_code == 201
        log_record = next(record for record in caplog.records if record.getMessage() == "scan.stale.auto_failed")
        assert log_record.request_id == "req-stale-1"
        assert log_record.scan_id == "20000101T000003-k8s"
        assert log_record.status_before == SCAN_STATUS_CREATED
        assert log_record.status_after == SCAN_STATUS_FAILED
        assert log_record.stale_rule == "created_timeout"
        assert log_record.failure_source == "auto"
        assert log_record.trigger_endpoint == "/api/v1/scans/start"


class TestUploadUrl:
    def test_returns_upload_url_and_s3_key(self, client):
        start_resp = _start(client)
        scan_id = _scan_id_for(start_resp, "k8s")
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert resp.status_code == 200
        data = resp.json()
        assert "upload_url" in data
        assert "s3_key" in data

    def test_s3_key_contains_scan_id(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert scan_id in resp.json()["s3_key"]

    def test_updates_status_to_uploading(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        _upload_url(client, scan_id)
        status = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"]
        assert status == SCAN_STATUS_UPLOADING

    def test_scan_not_found_returns_404(self, client):
        resp = _upload_url(client, "nonexistent-scan-id")
        assert resp.status_code == 404

    def test_non_json_file_rejected(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        resp = _upload_url(client, scan_id, file_name="scan.txt")
        assert resp.status_code == 422

    def test_s3_keys_updated_on_upload(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert resp.json()["s3_key"].endswith("k8s-snapshot.json")


class TestCompleteScan:
    def test_complete_updates_status_to_completed(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        resp = _complete(client, scan_id)
        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_COMPLETED

    def test_complete_stores_s3_keys(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        url_resp = _upload_url(client, scan_id)
        s3_key = url_resp.json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()
        assert s3_key in status_resp["s3_keys"]

    def test_complete_sets_completed_at(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        _complete(client, scan_id)

        status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
        data = status_resp.json()
        assert data["status"] == SCAN_STATUS_COMPLETED
        assert data["completed_at"] is not None

    def test_complete_from_processing_transitions_to_completed(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": [f"scans/a1b2c3d4-e5f6-7890-abcd-ef1234567890/{scan_id}/k8s/k8s-snapshot.json"]},
        )
        assert resp.status_code == 202
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_COMPLETED

    def test_complete_scan_not_found_returns_404(self, client):
        resp = client.post("/api/v1/scans/ghost-scan/complete", json={"files": ["some/key.json"]})
        assert resp.status_code == 404

    def test_complete_requires_processing_or_uploading(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": ["scans/c1/s1/k8s/k8s-snapshot.json"]},
        )
        assert resp.status_code == 409

    def test_complete_rejects_other_cluster_scan(self, client):
        scan_id = _scan_id_for(_start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901"), "aws")
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": [f"scans/other/{scan_id}/k8s/k8s-snapshot.json"]},
        )
        assert resp.status_code == 403

    def test_complete_empty_files_rejected(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        resp = client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": []})
        assert resp.status_code == 422

    def test_complete_missing_s3_file_returns_400(self, client_missing_s3):
        scan_id = _scan_id_for(_start(client_missing_s3), "k8s")
        _claim(client_missing_s3)
        resp = _complete(client_missing_s3, scan_id)
        assert resp.status_code == 400

    def test_complete_missing_s3_file_keeps_scan_not_completed(self, client_missing_s3_with_repo):
        client, repo = client_missing_s3_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)

        resp = _complete(client, scan_id)

        assert resp.status_code == 400
        record = repo._store[scan_id]
        assert record.status == SCAN_STATUS_UPLOADING
        assert record.completed_at is None

    def test_complete_keeps_analysis_lifecycle_separate(self, client_with_analysis_repo):
        client, repo, jobs_repo = client_with_analysis_repo
        k8s_start = _start(client)

        for scanner_type, scan_id in (
            ("k8s", _scan_id_for(k8s_start, "k8s")),
            ("image", _scan_id_for(k8s_start, "image")),
        ):
            _claim(client, scanner_type=scanner_type)
            resp = _complete(client, scan_id)
            assert resp.status_code == 202
            assert repo._store[scan_id].status == SCAN_STATUS_COMPLETED

        assert jobs_repo.jobs == []
        assert all(record.status == SCAN_STATUS_COMPLETED for record in repo._store.values())

    def test_complete_emits_lifecycle_logs(self, caplog):
        repo = FakeScanRepository()
        s3 = FakeS3Service()
        clusters = FakeClusterRepository()
        analysis = AnalysisService(jobs_repo=FakeAnalysisJobRepository(), scan_repo=repo)
        service = ScanService(scan_repository=repo, s3_service=s3, analysis_service=analysis, cluster_repository=clusters)
        app.dependency_overrides[get_scan_service] = lambda: service
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
                id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                name="test-cluster",
                description=None,
                cluster_type="eks",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )

        app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
        try:
            with caplog.at_level(logging.INFO):
                with TestClient(app) as client:
                    scan_id = _scan_id_for(_start(client), "k8s")
                    _claim(client)
                    s3_key = _upload_url(client, scan_id).json()["s3_key"]
                    complete_resp = client.post(
                        f"/api/v1/scans/{scan_id}/complete",
                        headers={"X-Request-ID": "req-complete-1"},
                        json={"files": [s3_key]},
                    )

            assert complete_resp.status_code == 202
            records = _scan_log_records(caplog)
            events = [record.getMessage() for record in records]
            assert "scan.complete.request_received" in events
            assert "scan.complete.accepted" in events

            request_received = next(record for record in records if record.getMessage() == "scan.complete.request_received")
            assert request_received.request_id == "req-complete-1"
            assert request_received.scan_id == scan_id
            assert request_received.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

            accepted = next(record for record in records if record.getMessage() == "scan.complete.accepted")
            assert accepted.request_id == "req-complete-1"
            assert accepted.scan_id == scan_id
            assert accepted.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            assert accepted.scanner_type == "k8s"
            assert accepted.status_before == SCAN_STATUS_UPLOADING
            assert accepted.status_after == SCAN_STATUS_COMPLETED
        finally:
            app.dependency_overrides.clear()


class TestManualFail:
    def test_manual_fail_requires_jwt(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.post(f"/api/v1/scans/{scan_id}/fail")

        assert resp.status_code == 401

    def test_manual_fail_created_scan(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client))

        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_FAILED
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_FAILED

    def test_manual_fail_processing_scan(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client))

        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_FAILED

    def test_manual_fail_uploading_scan(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        _upload_url(client, scan_id)

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client))

        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_FAILED

    def test_manual_fail_completed_is_idempotent(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        s3_key = _upload_url(client, scan_id).json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client))

        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_COMPLETED

    def test_manual_fail_failed_is_idempotent(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        repo._store[scan_id].status = SCAN_STATUS_FAILED

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client))

        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_FAILED

    def test_manual_fail_not_visible_to_other_user(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        repo._store[scan_id].user_id = "user-1"

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers=_auth_headers(client, "user-2"))

        assert resp.status_code == 404
        assert repo._store[scan_id].status == SCAN_STATUS_CREATED

    def test_x_user_id_alone_does_not_drive_fail_route(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.post(f"/api/v1/scans/{scan_id}/fail", headers={"X-User-Id": "user-1"})

        assert resp.status_code == 401

    def test_manual_fail_emits_logs(self, client, caplog):
        scan_id = _scan_id_for(_start(client), "k8s")

        with caplog.at_level(logging.INFO):
            resp = client.post(
                f"/api/v1/scans/{scan_id}/fail",
                headers={**_auth_headers(client), "X-Request-ID": "req-fail-1"},
            )

        assert resp.status_code == 202
        events = [record.getMessage() for record in caplog.records]
        assert "scan.fail.request_received" in events
        assert "scan.fail.accepted" in events
        accepted = next(record for record in caplog.records if record.getMessage() == "scan.fail.accepted")
        assert accepted.request_id == "req-fail-1"
        assert accepted.scan_id == scan_id
        assert accepted.status_before == SCAN_STATUS_CREATED
        assert accepted.status_after == SCAN_STATUS_FAILED
        assert accepted.failure_source == "manual"


class TestScanStatus:
    def test_get_status_requires_jwt(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.get(f"/api/v1/scans/{scan_id}/status")

        assert resp.status_code == 401

    def test_get_status_created(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == SCAN_STATUS_CREATED
        assert data["scan_id"] == scan_id

    def test_get_status_not_found(self, client):
        resp = client.get("/api/v1/scans/ghost-id/status", headers=_auth_headers(client))
        assert resp.status_code == 404

    def test_status_transitions_created_processing_uploading_completed(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_CREATED
        _claim(client)
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_PROCESSING
        _upload_url(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_UPLOADING
        _complete(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client)).json()["status"] == SCAN_STATUS_COMPLETED

    def test_get_status_not_visible_to_other_user(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        repo._store[scan_id].user_id = "user-1"

        resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=_auth_headers(client, "user-2"))

        assert resp.status_code == 404


class TestScanDetail:
    def test_get_detail_requires_jwt(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.get(f"/api/v1/scans/{scan_id}")

        assert resp.status_code == 401

    def test_get_detail_returns_scan_metadata(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.get(f"/api/v1/scans/{scan_id}", headers=_auth_headers(client))

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["cluster_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert data["scanner_type"] == "k8s"
        assert data["status"] == SCAN_STATUS_CREATED
        assert data["s3_keys"] == []
        assert data["created_at"] is not None
        assert data["completed_at"] is None

    def test_get_detail_returns_s3_keys_after_complete(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        s3_key = _upload_url(client, scan_id).json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])

        resp = client.get(f"/api/v1/scans/{scan_id}", headers=_auth_headers(client))

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == SCAN_STATUS_COMPLETED
        assert data["s3_keys"] == [s3_key]
        assert data["completed_at"] is not None

    def test_get_detail_not_found(self, client):
        resp = client.get("/api/v1/scans/ghost-id", headers=_auth_headers(client))
        assert resp.status_code == 404

    def test_get_detail_not_visible_to_other_user(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        repo._store[scan_id].user_id = "user-1"

        resp = client.get(f"/api/v1/scans/{scan_id}", headers=_auth_headers(client, "user-2"))

        assert resp.status_code == 404


class TestRawScanResultUrl:
    def test_get_raw_result_url_returns_presigned_download_url(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        _claim(client)
        s3_key = _upload_url(client, scan_id).json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url", headers=_auth_headers(client))

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["s3_key"] == s3_key
        assert data["download_url"].startswith(f"https://fake-s3.example.com/{s3_key}")
        assert data["expires_in"] == 600

    def test_get_raw_result_url_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        resp = client.get("/api/v1/scans/any-scan-id/raw-result-url")
        assert resp.status_code == 401

    def test_get_raw_result_url_not_found_when_scan_missing(self, client):
        resp = client.get("/api/v1/scans/ghost-id/raw-result-url", headers=_auth_headers(client))
        assert resp.status_code == 404

    def test_get_raw_result_url_not_found_when_no_s3_keys(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url", headers=_auth_headers(client))

        assert resp.status_code == 404

    def test_get_raw_result_url_rejects_multiple_s3_keys(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _scan_id_for(_start(client), "k8s")
        record = repo._store[scan_id]
        record.s3_keys = [
            f"scans/{record.cluster_id}/{scan_id}/{record.scanner_type}/{record.scanner_type}-snapshot.json",
            f"scans/{record.cluster_id}/{scan_id}/{record.scanner_type}/extra.json",
        ]

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url", headers=_auth_headers(client))

        assert resp.status_code == 409


class TestClusterScanList:
    def test_list_cluster_scans_requires_jwt(self, client):
        resp = client.get("/api/v1/clusters/cluster-1/scans")

        assert resp.status_code == 401

    def test_list_cluster_scans_returns_scan_summaries_newest_first(self, client_with_repo):
        client, repo = client_with_repo
        older = _FakeScanRecord(
            scan_id="older-scan",
            cluster_id="cluster-1",
            scanner_type="k8s",
            user_id="user-1",
            status=SCAN_STATUS_COMPLETED,
            s3_keys=["scans/cluster-1/older-scan/k8s/k8s-snapshot.json"],
            created_at=datetime(2026, 3, 9, 10, 0, 0),
            completed_at=datetime(2026, 3, 9, 10, 5, 0),
            request_source="manual",
            requested_at=datetime(2026, 3, 9, 9, 59, 0),
        )
        newer = _FakeScanRecord(
            scan_id="newer-scan",
            cluster_id="cluster-1",
            scanner_type="aws",
            user_id="user-1",
            status=SCAN_STATUS_PROCESSING,
            s3_keys=[],
            created_at=datetime(2026, 3, 10, 10, 0, 0),
            completed_at=None,
            request_source="manual",
            requested_at=datetime(2026, 3, 10, 9, 59, 0),
        )
        other_cluster = _FakeScanRecord(
            scan_id="other-scan",
            cluster_id="cluster-2",
            scanner_type="image",
            user_id="user-2",
            status=SCAN_STATUS_CREATED,
            s3_keys=[],
            created_at=datetime(2026, 3, 11, 10, 0, 0),
            completed_at=None,
            request_source="manual",
            requested_at=datetime(2026, 3, 11, 9, 59, 0),
        )
        repo._store = {
            older.scan_id: older,
            newer.scan_id: newer,
            other_cluster.scan_id: other_cluster,
        }

        resp = client.get("/api/v1/clusters/cluster-1/scans", headers=_auth_headers(client))

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert [item["scan_id"] for item in data["items"]] == ["newer-scan", "older-scan"]
        assert data["items"][0]["file_count"] == 0
        assert data["items"][0]["has_raw_result"] is False
        assert data["items"][1]["file_count"] == 1
        assert data["items"][1]["has_raw_result"] is True

    def test_list_cluster_scans_returns_empty_result_for_unknown_cluster(self, client):
        resp = client.get("/api/v1/clusters/unknown-cluster/scans", headers=_auth_headers(client))

        assert resp.status_code == 200
        assert resp.json() == {"items": [], "total": 0}

    def test_list_cluster_scans_only_returns_authenticated_users_scans(self, client_with_repo):
        client, repo = client_with_repo
        repo._store = {
            "scan-user-1": _FakeScanRecord(
                scan_id="scan-user-1",
                cluster_id="cluster-1",
                scanner_type="k8s",
                user_id="user-1",
                status=SCAN_STATUS_CREATED,
                s3_keys=[],
                created_at=datetime(2026, 3, 11, 10, 0, 0),
                completed_at=None,
                request_source="manual",
                requested_at=datetime(2026, 3, 11, 9, 59, 0),
            ),
            "scan-user-2": _FakeScanRecord(
                scan_id="scan-user-2",
                cluster_id="cluster-1",
                scanner_type="aws",
                user_id="user-2",
                status=SCAN_STATUS_CREATED,
                s3_keys=[],
                created_at=datetime(2026, 3, 12, 10, 0, 0),
                completed_at=None,
                request_source="manual",
                requested_at=datetime(2026, 3, 12, 9, 59, 0),
            ),
        }

        resp = client.get("/api/v1/clusters/cluster-1/scans", headers=_auth_headers(client, "user-1"))

        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert [item["scan_id"] for item in resp.json()["items"]] == ["scan-user-1"]


class TestClaimPendingScan:
    def test_claims_one_created_scan(self, client):
        scan_id = _scan_id_for(_start(client), "k8s")
        resp = client.get(
            "/api/v1/scans/pending",
            params={
                "scanner_type": "k8s",
                "claimed_by": "worker-1",
                "lease_seconds": 120,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == "processing"
        assert data["claimed_by"] == "worker-1"
        assert data["claimed_at"] is not None
        assert data["started_at"] is not None
        assert data["lease_expires_at"] is not None

    def test_claim_returns_only_matching_cluster_and_scanner(self, client):
        auth_cluster = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        other_cluster = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        target = _scan_id_for(_start(client, cluster_id=auth_cluster), "k8s")
        _start(client, cluster_id=other_cluster)

        resp = _claim(client, scanner_type="k8s", claimed_by="worker-1")
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == target

        no_more_target = _claim(client, scanner_type="k8s", claimed_by="worker-2")
        assert no_more_target.status_code == 204

    def test_returns_204_when_no_created(self, client):
        resp = client.get(
            "/api/v1/scans/pending",
            params={
                "scanner_type": "k8s",
                "claimed_by": "worker-1",
            },
        )
        assert resp.status_code == 204

    def test_claimed_by_defaults_when_missing(self, client):
        _start(client)
        resp = _claim(client, scanner_type="k8s")
        assert resp.status_code == 200
        assert resp.json()["claimed_by"] == "unknown-worker"

    def test_pending_logs_distinguish_no_work_and_claimed(self, client, caplog):
        with caplog.at_level(logging.INFO):
            no_work = _claim(client, scanner_type="k8s", claimed_by="worker-a")
            _start(client)
            claimed = _claim(client, scanner_type="k8s", claimed_by="worker-b")

        assert no_work.status_code == 204
        assert claimed.status_code == 200

        records = _scan_log_records(caplog)
        events = [record.getMessage() for record in records]
        assert "scan.pending.poll_received" in events
        assert "scan.pending.no_work_found" in events
        assert "scan.pending.claimed" in events

        no_work_record = next(record for record in records if record.getMessage() == "scan.pending.no_work_found")
        assert no_work_record.claimed_by == "worker-a"
        assert no_work_record.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert no_work_record.scanner_type == "k8s"

        claimed_record = next(record for record in records if record.getMessage() == "scan.pending.claimed")
        assert claimed_record.claimed_by == "worker-b"
        assert claimed_record.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert claimed_record.scanner_type == "k8s"
        assert claimed_record.status_before == SCAN_STATUS_CREATED
        assert claimed_record.status_after == SCAN_STATUS_PROCESSING
        assert claimed_record.scan_id == claimed.json()["scan_id"]


def test_openapi_scan_flow_documents_producer_worker_model(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()

    start_op = spec["paths"]["/api/v1/scans/start"]["post"]
    pending_op = spec["paths"]["/api/v1/scans/pending"]["get"]
    scans_tag = next(tag for tag in spec["tags"] if tag["name"] == "Scans")

    assert start_op["summary"] == "스캔 작업 큐 생성"
    assert "작업 등록 API" in start_op["description"]
    assert "스캔을 직접 실행하지 않으며" in start_op["description"]
    assert "대시보드 또는 스케줄러가 `/start`를 호출" in start_op["description"]

    assert pending_op["summary"] == "워커용 created 작업 클레임"
    assert "워커 클레임 API" in pending_op["description"]
    assert "`/start`가 생성한 작업만" in pending_op["description"]
    assert "실제로 실행할 created 작업" in pending_op["description"]
    assert "작업 생성" in scans_tag["description"]
