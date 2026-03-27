from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_authenticated_cluster, get_current_user
from app.application.di import get_runtime_snapshot_service
from app.main import app
from app.models.schemas import ClusterResponse, UserSummaryResponse


class FakeRuntimeSnapshotService:
    def __init__(self):
        self.rows = []
        self.existing_keys = set()

    async def get_upload_url(self, authenticated_cluster_id: str):
        uploaded_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        s3_key = f"runtime/{authenticated_cluster_id}/{uploaded_at.strftime('%Y%m%dT%H%M%SZ')}/events.json"
        self.existing_keys.add(s3_key)
        return {
            "upload_url": f"https://example.com/{s3_key}",
            "s3_key": s3_key,
            "expires_in": 600,
        }

    async def complete_upload(self, authenticated_cluster_id: str, s3_key: str, snapshot_at: datetime, fact_count: int | None):
        row = {
            "upload_id": "upload-1",
            "cluster_id": authenticated_cluster_id,
            "s3_key": s3_key,
            "snapshot_at": snapshot_at,
            "uploaded_at": datetime(2026, 3, 27, 12, 5, 0, tzinfo=timezone.utc),
            "fact_count": fact_count,
        }
        self.rows.append(row)
        return row

    async def get_status(self, cluster_id: str, user_id: str):
        if cluster_id == "cluster-1" and user_id == "user-1":
            return {
                "cluster_id": cluster_id,
                "last_uploaded_at": datetime(2026, 3, 27, 12, 5, 0, tzinfo=timezone.utc),
                "snapshot_at": datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
                "fact_count": 0,
                "is_stale": False,
            }
        return {
            "cluster_id": cluster_id,
            "last_uploaded_at": None,
            "snapshot_at": None,
            "fact_count": None,
            "is_stale": True,
        }


@pytest.fixture
def client():
    service = FakeRuntimeSnapshotService()
    app.dependency_overrides[get_runtime_snapshot_service] = lambda: service

    async def _fake_auth_cluster():
        return ClusterResponse(
            id="cluster-1",
            name="cluster-1",
            description=None,
            cluster_type="eks",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

    async def _fake_current_user():
        return UserSummaryResponse(
            id="user-1",
            email="user-1@example.com",
            name="User 1",
            is_active=True,
        )

    app.dependency_overrides[get_authenticated_cluster] = _fake_auth_cluster
    app.dependency_overrides[get_current_user] = _fake_current_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_runtime_upload_url_requires_authorization_header():
    app.dependency_overrides.clear()
    with TestClient(app) as client:
        response = client.post("/api/v1/runtime/upload-url")
    assert response.status_code == 401


def test_runtime_upload_url_returns_runtime_key(client):
    response = client.post("/api/v1/runtime/upload-url", headers={"Authorization": "Bearer token"})

    assert response.status_code == 200
    body = response.json()
    assert body["s3_key"] == "runtime/cluster-1/20260327T120000Z/events.json"
    assert body["expires_in"] == 600


def test_runtime_complete_accepts_fact_count_zero(client):
    response = client.post(
        "/api/v1/runtime/complete",
        headers={"Authorization": "Bearer token"},
        json={
            "s3_key": "runtime/cluster-1/20260327T120000Z/events.json",
            "snapshot_at": "2026-03-27T12:00:00Z",
            "fact_count": 0,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == "cluster-1"
    assert body["fact_count"] == 0


def test_runtime_status_uses_user_auth_and_hides_s3_key(client):
    response = client.get(
        "/api/v1/clusters/cluster-1/runtime/status",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "cluster_id": "cluster-1",
        "last_uploaded_at": "2026-03-27T12:05:00Z",
        "snapshot_at": "2026-03-27T12:00:00Z",
        "fact_count": 0,
        "is_stale": False,
    }
