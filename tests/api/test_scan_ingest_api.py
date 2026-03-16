from __future__ import annotations

from datetime import datetime
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

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
        request_source: str = "unknown",
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
        return {}

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

    def verify_file_exists(self, s3_key: str) -> bool:
        return True


class FakeS3ServiceMissingFile(FakeS3Service):
    def verify_file_exists(self, s3_key: str) -> bool:
        return False


@pytest.fixture
def client():
    repo = FakeScanRepository()
    s3 = FakeS3Service()
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_missing_s3():
    repo = FakeScanRepository()
    s3 = FakeS3ServiceMissingFile()
    service = ScanService(scan_repository=repo, s3_service=s3)
    app.dependency_overrides[get_scan_service] = lambda: service
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _start(
    client,
    cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    scanner_type="k8s",
    request_source="scanner-orchestrator",
):
    return client.post(
        "/api/v1/scans/start",
        json={"cluster_id": cluster_id, "scanner_type": scanner_type, "request_source": request_source},
    )


def _upload_url(client, scan_id, file_name="scan.json"):
    return client.post(f"/api/v1/scans/{scan_id}/upload-url", json={"file_name": file_name})


def _claim(
    client,
    cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    scanner_type="k8s",
    claimed_by="worker-1",
    lease_seconds=300,
):
    return client.get(
        "/api/v1/scans/pending",
        params={
            "cluster_id": cluster_id,
            "scanner_type": scanner_type,
            "claimed_by": claimed_by,
            "lease_seconds": lease_seconds,
        },
    )


def _complete(client, scan_id, files=None):
    if files is None:
        resp = _upload_url(client, scan_id)
        files = [resp.json()["s3_key"]]
    return client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": files})


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
    def test_complete_updates_status_to_processing(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = _complete(client, scan_id)
        assert resp.status_code == 202
        assert resp.json()["status"] == SCAN_STATUS_PROCESSING

    def test_complete_stores_s3_keys(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        url_resp = _upload_url(client, scan_id)
        s3_key = url_resp.json()["s3_key"]
        _complete(client, scan_id, files=[s3_key])
        status_resp = client.get(f"/api/v1/scans/{scan_id}/status").json()
        assert s3_key in status_resp["files"]

    def test_complete_from_running_transitions_to_processing(self, client):
        scan_id = _start(client).json()["scan_id"]
        _claim(client)
        resp = client.post(
            f"/api/v1/scans/{scan_id}/complete",
            json={"files": [f"scans/a1b2c3d4-e5f6-7890-abcd-ef1234567890/{scan_id}/k8s/scan.json"]},
        )
        assert resp.status_code == 202
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_PROCESSING

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

    def test_complete_empty_files_rejected(self, client):
        scan_id = _start(client).json()["scan_id"]
        resp = client.post(f"/api/v1/scans/{scan_id}/complete", json={"files": []})
        assert resp.status_code == 422

    def test_complete_missing_s3_file_returns_400(self, client_missing_s3):
        scan_id = _start(client_missing_s3).json()["scan_id"]
        _claim(client_missing_s3)
        resp = _complete(client_missing_s3, scan_id)
        assert resp.status_code == 400


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

    def test_status_transitions_queued_uploading_processing(self, client):
        scan_id = _start(client).json()["scan_id"]
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_QUEUED
        _claim(client)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_RUNNING
        _upload_url(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_UPLOADING
        _complete(client, scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}/status").json()["status"] == SCAN_STATUS_PROCESSING


class TestClaimPendingScan:
    def test_claims_one_queued_scan(self, client):
        scan_id = _start(client).json()["scan_id"]
        resp = client.get(
            "/api/v1/scans/pending",
            params={
                "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
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
        target_cluster = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        other_cluster = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        target = _start(client, cluster_id=target_cluster, scanner_type="k8s").json()["scan_id"]
        _start(client, cluster_id=target_cluster, scanner_type="aws")
        _start(client, cluster_id=other_cluster, scanner_type="image")

        resp = _claim(client, cluster_id=target_cluster, scanner_type="k8s", claimed_by="worker-1")
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == target

        no_more_target = _claim(client, cluster_id=target_cluster, scanner_type="k8s", claimed_by="worker-2")
        assert no_more_target.status_code == 204

    def test_returns_204_when_no_queued(self, client):
        resp = client.get(
            "/api/v1/scans/pending",
            params={
                "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "scanner_type": "k8s",
                "claimed_by": "worker-1",
            },
        )
        assert resp.status_code == 204
