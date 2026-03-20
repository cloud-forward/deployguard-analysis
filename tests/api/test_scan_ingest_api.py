from __future__ import annotations

from datetime import datetime
import logging
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster
from app.application.services.analysis_service import AnalysisService
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService
from app.core.constants import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_PROCESSING,
    SCAN_STATUS_UPLOADING,
)
from app.main import app
from app.models.schemas import ClusterResponse


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
    def __init__(self):
        self._store: dict = {}

    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        status: str = SCAN_STATUS_QUEUED,
        request_source: str = "manual",
        requested_at=None,
    ):
        if scan_id in self._store:
            raise ValueError(f"Duplicate scan_id: {scan_id}")
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
            if r.cluster_id == cluster_id and r.scanner_type == scanner_type and r.status == SCAN_STATUS_QUEUED
        ]
        if not queued:
            return None
        queued.sort(key=lambda r: r.requested_at)
        record = queued[0]
        record.status = "running"
        record.claimed_by = claimed_by
        record.claimed_at = started_at
        record.started_at = started_at
        record.lease_expires_at = lease_expires_at
        return record


class FakeS3Service:
    def generate_presigned_upload_url(self, cluster_id, scan_id, scanner_type, file_name, expires_in=600):
        s3_key = f"scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}"
        return f"https://fake-s3.example.com/{s3_key}", s3_key

    def generate_presigned_download_url(self, s3_key: str, expires_in: int = 600) -> str:
        return f"https://fake-s3.example.com/{s3_key}?download=1&X-Amz-Expires={expires_in}"

    def verify_file_exists(self, s3_key: str) -> bool:
        return True


class FakeS3ServiceMissingFile(FakeS3Service):
    def verify_file_exists(self, s3_key: str) -> bool:
        return False


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
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
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
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
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
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
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
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
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
    jobs_repo = FakeAnalysisJobRepository()
    analysis = AnalysisService(jobs_repo=jobs_repo, scan_repo=repo)
    service = ScanService(scan_repository=repo, s3_service=s3, analysis_service=analysis)
    app.dependency_overrides[get_scan_service] = lambda: service
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


def _start(
    client,
    cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    scanner_type="k8s",
    request_source="manual",
):
    return client.post(
        "/api/v1/scans/start",
        json={"cluster_id": cluster_id, "scanner_type": scanner_type, "request_source": request_source},
    )


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
    def test_creates_scan_record(self, client):
        resp = _start(client)
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == SCAN_STATUS_QUEUED

    def test_scan_id_contains_scanner_type(self, client):
        resp = _start(client, scanner_type="aws")
        assert "aws" in resp.json()["scan_id"]

    def test_invalid_scanner_type_rejected(self, client):
        resp = _start(client, scanner_type="unknown-scanner")
        assert resp.status_code == 422

    def test_manual_request_source_accepted(self, client):
        resp = _start(client, request_source="manual")
        assert resp.status_code == 201

    def test_scheduled_request_source_accepted(self, client):
        resp = _start(client, request_source="scheduled")
        assert resp.status_code == 201

    def test_omitted_request_source_uses_valid_default(self, client):
        resp = client.post(
            "/api/v1/scans/start",
            json={
                "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "scanner_type": "k8s",
            },
        )
        assert resp.status_code == 201

    def test_invalid_request_source_rejected(self, client):
        resp = _start(client, request_source="api")
        assert resp.status_code == 422

    def test_invalid_request_source_does_not_create_record(self, client_with_repo):
        client, repo = client_with_repo
        resp = _start(client, request_source="api")
        assert resp.status_code == 422
        assert repo._store == {}

    def test_missing_cluster_id_rejected(self, client):
        resp = client.post("/api/v1/scans/start", json={"scanner_type": "k8s"})
        assert resp.status_code == 422

    def test_missing_scanner_type_rejected(self, client):
        resp = client.post("/api/v1/scans/start", json={"cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})
        assert resp.status_code == 422

    def test_duplicate_active_scan_rejected(self, client):
        _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="k8s")
        resp = _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="k8s")
        assert resp.status_code == 409

    def test_different_scanner_types_allowed_same_cluster(self, client):
        assert _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="k8s").status_code == 201
        assert _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="aws").status_code == 201

    def test_same_scanner_type_different_clusters_allowed(self, client):
        r1 = _start(client, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="k8s")
        r2 = _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901", scanner_type="aws")
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["scan_id"] != r2.json()["scan_id"]

    def test_scan_start_with_unknown_cluster_still_creates_record(self, client):
        resp = _start(client, cluster_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
        assert resp.status_code == 201

    def test_start_emits_lifecycle_logs(self, client, caplog):
        with caplog.at_level(logging.INFO):
            resp = client.post(
                "/api/v1/scans/start",
                headers={"X-Request-ID": "req-start-1"},
                json={
                    "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "scanner_type": "k8s",
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
        assert request_received.scanner_type == "k8s"
        assert request_received.request_source == "manual"

        record_created = next(record for record in records if record.getMessage() == "scan.start.record_created")
        assert record_created.request_id == "req-start-1"
        assert record_created.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert record_created.scanner_type == "k8s"
        assert record_created.request_source == "manual"
        assert record_created.status_after == SCAN_STATUS_QUEUED
        assert record_created.scan_id == resp.json()["scan_id"]


class TestUploadUrl:
    def test_returns_upload_url_and_s3_key(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert resp.status_code == 200
        data = resp.json()
        assert "upload_url" in data
        assert "s3_key" in data

    def test_s3_key_contains_scan_id(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert scan_id in resp.json()["s3_key"]

    def test_updates_status_to_uploading(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        _upload_url(client, scan_id)
        status = client.get(f"/api/v1/scans/{scan_id}/status").json()["status"]
        assert status == SCAN_STATUS_UPLOADING

    def test_scan_not_found_returns_404(self, client):
        resp = _upload_url(client, "nonexistent-scan-id")
        assert resp.status_code == 404

    def test_non_json_file_rejected(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _upload_url(client, scan_id, file_name="scan.txt")
        assert resp.status_code == 422

    def test_s3_keys_updated_on_upload(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _upload_url(client, scan_id)
        assert resp.json()["s3_key"].endswith("scan.json")


class TestCompleteScan:
    def test_complete_updates_status_to_completed(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _complete(client, scan_id)
        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_COMPLETED

    def test_complete_stores_s3_keys(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        url_resp = _upload_url(client, scan_id)
        s3_key = url_resp.json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status").json()
        assert s3_key in status_resp["files"]

    def test_complete_sets_completed_at(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        _complete(client, scan_id)

        status_resp = client.get(f"/api/v1/scans/{scan_id}/status")
        data = status_resp.json()
        assert data["status"] == SCAN_STATUS_COMPLETED
        assert data["completed_at"] is not None

    def test_complete_from_running_transitions_to_completed(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": [f"scans/a1b2c3d4-e5f6-7890-abcd-ef1234567890/{scan_id}/k8s/scan.json"]},
        )
        assert resp.status_code == 202
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_COMPLETED

    def test_complete_scan_not_found_returns_404(self, client):
        resp = client.post("/api/v1/scans/ghost-scan/complete", json={"files": ["some/key.json"]})
        assert resp.status_code == 404

    def test_complete_requires_running_or_uploading(self, client):
        scan_id = _start(client).json()["scan_id"]
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": ["scans/c1/s1/k8s/f.json"]},
        )
        assert resp.status_code == 409

    def test_complete_rejects_other_cluster_scan(self, client):
        scan_id = _start(client, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901").json()["scan_id"]
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": [f"scans/other/{scan_id}/k8s/scan.json"]},
        )
        assert resp.status_code == 403

    def test_complete_empty_files_rejected(self, client):
        scan_id = _start(client).json()["scan_id"]
        resp = client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": []})
        assert resp.status_code == 422

    def test_complete_missing_s3_file_returns_400(self, client_missing_s3):
        scan_id = _start(client_missing_s3).json()["scan_id"]
        _claim(client_missing_s3)
        resp = _complete(client_missing_s3, scan_id)
        assert resp.status_code == 400

    def test_complete_missing_s3_file_keeps_scan_not_completed(self, client_missing_s3_with_repo):
        client, repo = client_missing_s3_with_repo
        scan_id = _start(client).json()["scan_id"]
        _claim(client)

        resp = _complete(client, scan_id)

        assert resp.status_code == 400
        record = repo._store[scan_id]
        assert record.status == SCAN_STATUS_UPLOADING
        assert record.completed_at is None

    def test_complete_keeps_analysis_lifecycle_separate(self, client_with_analysis_repo):
        client, repo, jobs_repo = client_with_analysis_repo

        for scanner_type in ("k8s", "aws", "image"):
            scan_id = _start(client, scanner_type=scanner_type).json()["scan_id"]
            _claim(client, scanner_type=scanner_type)
            resp = _complete(client, scan_id)
            assert resp.status_code == 202
            assert repo._store[scan_id].status == SCAN_STATUS_COMPLETED

        assert len(jobs_repo.jobs) == 1
        assert jobs_repo.jobs[0]["cluster_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert jobs_repo.jobs[0]["status"] == "pending"
        assert all(record.status == SCAN_STATUS_COMPLETED for record in repo._store.values())

    def test_complete_emits_lifecycle_logs(self, caplog):
        repo = FakeScanRepository()
        s3 = FakeS3Service()
        analysis = AnalysisService(jobs_repo=FakeAnalysisJobRepository(), scan_repo=repo)
        service = ScanService(scan_repository=repo, s3_service=s3, analysis_service=analysis)
        app.dependency_overrides[get_scan_service] = lambda: service

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
                    scan_id = _start(client).json()["scan_id"]
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
            assert "scan.analysis.trigger_check_invoked" in events

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

            trigger_check = next(record for record in records if record.getMessage() == "scan.analysis.trigger_check_invoked")
            assert trigger_check.request_id == "req-complete-1"
            assert trigger_check.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        finally:
            app.dependency_overrides.clear()


class TestScanStatus:
    def test_get_status_created(self, client):
        scan_id = _start(client).json()["scan_id"]
        resp = client.get(f"/api/v1/scans/{scan_id}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == SCAN_STATUS_QUEUED
        assert data["scan_id"] == scan_id

    def test_get_status_not_found(self, client):
        resp = client.get("/api/v1/scans/ghost-id/status")
        assert resp.status_code == 404

    def test_status_transitions_queued_uploading_completed(self, client):
        scan_id = _start(client).json()["scan_id"]
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_QUEUED
        _claim(client)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_RUNNING
        _upload_url(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_UPLOADING
        _complete(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_COMPLETED


class TestScanDetail:
    def test_get_detail_returns_scan_metadata(self, client):
        scan_id = _start(client).json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["cluster_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert data["scanner_type"] == "k8s"
        assert data["status"] == SCAN_STATUS_QUEUED
        assert data["s3_keys"] == []
        assert data["created_at"] is not None
        assert data["completed_at"] is None

    def test_get_detail_returns_s3_keys_after_complete(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        s3_key = _upload_url(client, scan_id).json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])

        resp = client.get(f"/api/v1/scans/{scan_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == SCAN_STATUS_COMPLETED
        assert data["s3_keys"] == [s3_key]
        assert data["completed_at"] is not None

    def test_get_detail_not_found(self, client):
        resp = client.get("/api/v1/scans/ghost-id")
        assert resp.status_code == 404


class TestRawScanResultUrl:
    def test_get_raw_result_url_returns_presigned_download_url(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        s3_key = _upload_url(client, scan_id).json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url")

        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["s3_key"] == s3_key
        assert data["download_url"].startswith(f"https://fake-s3.example.com/{s3_key}")
        assert data["expires_in"] == 600

    def test_get_raw_result_url_not_found_when_scan_missing(self, client):
        resp = client.get("/api/v1/scans/ghost-id/raw-result-url")
        assert resp.status_code == 404

    def test_get_raw_result_url_not_found_when_no_s3_keys(self, client):
        scan_id = _start(client).json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url")

        assert resp.status_code == 404

    def test_get_raw_result_url_rejects_multiple_s3_keys(self, client_with_repo):
        client, repo = client_with_repo
        scan_id = _start(client).json()["scan_id"]
        record = repo._store[scan_id]
        record.s3_keys = [
            f"scans/{record.cluster_id}/{scan_id}/{record.scanner_type}/scan.json",
            f"scans/{record.cluster_id}/{scan_id}/{record.scanner_type}/extra.json",
        ]

        resp = client.get(f"/api/v1/scans/{scan_id}/raw-result-url")

        assert resp.status_code == 409


class TestClusterScanList:
    def test_list_cluster_scans_returns_scan_summaries_newest_first(self, client_with_repo):
        client, repo = client_with_repo
        older = _FakeScanRecord(
            scan_id="older-scan",
            cluster_id="cluster-1",
            scanner_type="k8s",
            status=SCAN_STATUS_COMPLETED,
            s3_keys=["scans/cluster-1/older-scan/k8s/scan.json"],
            created_at=datetime(2026, 3, 9, 10, 0, 0),
            completed_at=datetime(2026, 3, 9, 10, 5, 0),
            request_source="manual",
            requested_at=datetime(2026, 3, 9, 9, 59, 0),
        )
        newer = _FakeScanRecord(
            scan_id="newer-scan",
            cluster_id="cluster-1",
            scanner_type="aws",
            status=SCAN_STATUS_RUNNING,
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
            status=SCAN_STATUS_QUEUED,
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

        resp = client.get("/api/v1/clusters/cluster-1/scans")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert [item["scan_id"] for item in data["items"]] == ["newer-scan", "older-scan"]
        assert data["items"][0]["file_count"] == 0
        assert data["items"][0]["has_raw_result"] is False
        assert data["items"][1]["file_count"] == 1
        assert data["items"][1]["has_raw_result"] is True

    def test_list_cluster_scans_returns_empty_result_for_unknown_cluster(self, client):
        resp = client.get("/api/v1/clusters/unknown-cluster/scans")

        assert resp.status_code == 200
        assert resp.json() == {"items": [], "total": 0}


class TestClaimPendingScan:
    def test_claims_one_queued_scan(self, client):
        scan_id = _start(client).json()["scan_id"]
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
        assert data["status"] == "running"
        assert data["claimed_by"] == "worker-1"
        assert data["claimed_at"] is not None
        assert data["started_at"] is not None
        assert data["lease_expires_at"] is not None

    def test_claim_returns_only_matching_cluster_and_scanner(self, client):
        auth_cluster = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        other_cluster = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        target = _start(client, cluster_id=auth_cluster, scanner_type="k8s").json()["scan_id"]
        _start(client, cluster_id=auth_cluster, scanner_type="aws")
        _start(client, cluster_id=other_cluster, scanner_type="image")

        resp = _claim(client, scanner_type="k8s", claimed_by="worker-1")
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == target

        no_more_target = _claim(client, scanner_type="k8s", claimed_by="worker-2")
        assert no_more_target.status_code == 204

    def test_returns_204_when_no_queued(self, client):
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
            _start(client, scanner_type="k8s")
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
        assert claimed_record.status_before == SCAN_STATUS_QUEUED
        assert claimed_record.status_after == SCAN_STATUS_RUNNING
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

    assert pending_op["summary"] == "워커용 queued 작업 클레임"
    assert "워커 클레임 API" in pending_op["description"]
    assert "`/start`가 생성한 작업만" in pending_op["description"]
    assert "실제로 실행할 queued 작업" in pending_op["description"]
    assert "작업 생성" in scans_tag["description"]
