from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.application.services.runtime_snapshot_service import RuntimeSnapshotService


class FakeRuntimeSnapshotRepository:
    def __init__(self):
        self.rows = []

    async def create(self, cluster_id: str, s3_key: str, snapshot_at: datetime, uploaded_at: datetime, fact_count: int | None = None):
        for row in self.rows:
            if row.s3_key == s3_key:
                return row
        row = SimpleNamespace(
            id=f"upload-{len(self.rows) + 1}",
            cluster_id=cluster_id,
            s3_key=s3_key,
            snapshot_at=snapshot_at,
            uploaded_at=uploaded_at,
            fact_count=fact_count,
        )
        self.rows.append(row)
        return row

    async def get_latest_by_cluster_id(self, cluster_id: str):
        candidates = [row for row in self.rows if row.cluster_id == cluster_id]
        if not candidates:
            return None
        return sorted(candidates, key=lambda row: row.uploaded_at, reverse=True)[0]

    async def list_recent_by_cluster_id(self, cluster_id: str, limit: int):
        candidates = [row for row in self.rows if row.cluster_id == cluster_id]
        candidates.sort(key=lambda row: row.uploaded_at, reverse=True)
        return candidates[:limit]


class FakeClusterRepository:
    async def get_by_id(self, cluster_id: str, user_id: str | None = None):
        if cluster_id == "cluster-1" and user_id == "user-1":
            return SimpleNamespace(id=cluster_id, user_id=user_id)
        return None


class FakeS3Service:
    def __init__(self):
        self.existing_keys = set()
        self.payloads = {}

    def generate_runtime_presigned_upload_url(self, cluster_id: str, uploaded_at: datetime, expires_in: int = 600):
        key = f"runtime/{cluster_id}/{uploaded_at.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}/events.json"
        self.existing_keys.add(key)
        return f"https://example.com/{key}", key

    def verify_file_exists(self, s3_key: str) -> bool:
        return s3_key in self.existing_keys

    def load_json(self, s3_key: str):
        return self.payloads[s3_key]


@pytest.fixture
def service():
    return RuntimeSnapshotService(
        runtime_snapshot_repository=FakeRuntimeSnapshotRepository(),
        cluster_repository=FakeClusterRepository(),
        s3_service=FakeS3Service(),
    )


class TestRuntimeSnapshotService:
    @pytest.mark.asyncio
    async def test_get_upload_url_uses_runtime_key_format(self, service):
        response = await service.get_upload_url("cluster-1")

        assert response.s3_key.startswith("runtime/cluster-1/")
        assert response.s3_key.endswith("/events.json")
        assert response.expires_in == 600

    @pytest.mark.asyncio
    async def test_complete_upload_accepts_fact_count_zero(self, service):
        upload = await service.get_upload_url("cluster-1")
        snapshot_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)

        response = await service.complete_upload(
            authenticated_cluster_id="cluster-1",
            s3_key=upload.s3_key,
            snapshot_at=snapshot_at,
            fact_count=0,
        )

        assert response.cluster_id == "cluster-1"
        assert response.fact_count == 0

    @pytest.mark.asyncio
    async def test_complete_upload_rejects_foreign_cluster_key(self, service):
        with pytest.raises(HTTPException) as exc_info:
            await service.complete_upload(
                authenticated_cluster_id="cluster-1",
                s3_key="runtime/cluster-2/20260327T120000Z/events.json",
                snapshot_at=datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
                fact_count=None,
            )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_get_status_returns_stale_true_without_rows(self, service):
        response = await service.get_status("cluster-1", "user-1")

        assert response.last_uploaded_at is None
        assert response.snapshot_at is None
        assert response.fact_count is None
        assert response.is_stale is True

    @pytest.mark.asyncio
    async def test_get_activities_reads_latest_snapshot_and_builds_dashboard_items(self, service):
        upload = await service.get_upload_url("cluster-1")
        snapshot_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        await service.complete_upload(
            authenticated_cluster_id="cluster-1",
            s3_key=upload.s3_key,
            snapshot_at=snapshot_at,
            fact_count=2,
        )
        service._s3.payloads[upload.s3_key] = {
            "facts": [
                {
                    "observed_at": "2026-03-27T11:56:37Z",
                    "source": "k8s_audit",
                    "fact_family": "credential_access",
                    "fact_type": "secret_read",
                    "category": "k8s_api",
                    "action": "get",
                    "severity_hint": "high",
                    "actor": {
                        "namespace": "deployguard",
                        "pod_name": "api-6d4cf",
                        "service_account": "api",
                        "workload_name": "api",
                    },
                    "target": {
                        "name": "ecr-secret",
                        "type": "secret",
                        "resource": "secrets",
                        "namespace": "deployguard",
                    },
                    "scenario_tags": ["credential_access", "irsa_chain"],
                },
                {
                    "observed_at": "2026-03-27T11:50:00Z",
                    "source": "falco",
                    "fact_family": "execution",
                    "fact_type": "suspicious_process",
                    "category": "process",
                    "action": "exec",
                    "severity_hint": "medium",
                    "target": {"name": "curl"},
                    "scenario_tags": [],
                },
            ]
        }

        response = await service.get_activities("cluster-1", "user-1", limit=10, snapshot_limit=1)

        assert response.cluster_id == "cluster-1"
        assert response.snapshot_count == 1
        assert len(response.items) == 2
        assert response.items[0].fact_type == "secret_read"
        assert response.items[0].title == "Secret access detected"
        assert response.items[0].summary == "Secret ecr-secret was accessed in namespace deployguard"
        assert response.items[0].notable is True
        assert response.items[0].namespace == "deployguard"
        assert response.items[0].target == "ecr-secret"
        assert response.items[0].target_type == "secret"
        assert response.items[0].target_resource == "secrets"
        assert response.items[0].target_namespace == "deployguard"

    @pytest.mark.asyncio
    async def test_get_activities_returns_empty_items_for_empty_snapshot(self, service):
        upload = await service.get_upload_url("cluster-1")
        snapshot_at = datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
        await service.complete_upload(
            authenticated_cluster_id="cluster-1",
            s3_key=upload.s3_key,
            snapshot_at=snapshot_at,
            fact_count=0,
        )
        service._s3.payloads[upload.s3_key] = {"facts": []}

        response = await service.get_activities("cluster-1", "user-1", limit=10, snapshot_limit=1)

        assert response.snapshot_count == 1
        assert response.items == []

    @pytest.mark.asyncio
    async def test_get_activities_uses_recent_snapshots_and_limit(self, service):
        first_key = "runtime/cluster-1/20260327T120000Z/events.json"
        service._s3.existing_keys.add(first_key)
        await service.complete_upload(
            authenticated_cluster_id="cluster-1",
            s3_key=first_key,
            snapshot_at=datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
            fact_count=1,
        )
        service._s3.payloads[first_key] = {
            "facts": [
                {
                    "observed_at": "2026-03-27T12:00:00Z",
                    "fact_type": "network_connect",
                    "action": "connect",
                    "target": {"address": "10.0.0.10:443", "type": "network"},
                }
            ]
        }

        second_key = "runtime/cluster-1/20260327T120500Z/events.json"
        service._s3.existing_keys.add(second_key)
        await service.complete_upload(
            authenticated_cluster_id="cluster-1",
            s3_key=second_key,
            snapshot_at=datetime(2026, 3, 27, 12, 5, 0, tzinfo=timezone.utc),
            fact_count=1,
        )
        service._s3.payloads[second_key] = {
            "facts": [
                {
                    "observed_at": "2026-03-27T12:05:00Z",
                    "fact_type": "pod_exec",
                    "action": "create",
                    "actor": {"namespace": "prod", "pod_name": "web-abc"},
                }
            ]
        }

        response = await service.get_activities("cluster-1", "user-1", limit=1, snapshot_limit=2)

        assert response.snapshot_count == 2
        assert len(response.items) == 1
        assert response.items[0].fact_type == "pod_exec"
