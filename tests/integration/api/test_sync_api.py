from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.application.services.inventory_service as inventory_service_module
from app.application.di import get_cluster_service, get_inventory_service
from app.application.services.cluster_service import ClusterService
from app.application.services.inventory_service import InventoryService
from app.gateway.db.base import Base
from app.gateway.models import Cluster, InventorySnapshot
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.main import app

USER_HEADERS = {"X-User-Id": "user-1"}


@pytest.fixture
async def inventory_client(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "sync_api.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    monkeypatch.setattr(inventory_service_module, "assume_role", lambda role_arn: f"session-for:{role_arn}")
    monkeypatch.setattr(
        inventory_service_module,
        "collect_all_assets",
        lambda session, account_id, region: {
            "scan_id": "scan-123",
            "aws_account_id": account_id,
            "region": region,
            "scanned_at": "2026-03-19T12:00:00+00:00",
            "iam_roles": [],
            "iam_users": [],
            "s3_buckets": [{"name": "bucket-a", "arn": "arn:aws:s3:::bucket-a"}],
            "rds_instances": [],
            "ec2_instances": [],
        },
    )

    async def override_get_inventory_service():
        async with sessionmaker() as session:
            yield InventoryService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                inventory_snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
            )

    async def override_get_cluster_service():
        async with sessionmaker() as session:
            yield ClusterService(cluster_repository=SQLAlchemyClusterRepository(session))

    app.dependency_overrides[get_inventory_service] = override_get_inventory_service
    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    with TestClient(app) as client:
        yield {"client": client, "sessionmaker": sessionmaker}
    app.dependency_overrides.clear()
    await engine.dispose()


def test_sync_cluster_persists_snapshot(inventory_client):
    create_response = inventory_client["client"].post(
        "/api/v1/clusters",
        json={
            "name": "prod",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
            "aws_region": "ap-northeast-2",
        },
        headers=USER_HEADERS,
    )
    cluster_id = create_response.json()["id"]

    response = inventory_client["client"].post(f"/api/v1/clusters/{cluster_id}/sync")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "scan-123"
    assert body["cluster_id"] == cluster_id
    assert body["status"] == "success"

    inventory_response = inventory_client["client"].get(f"/api/v1/clusters/{cluster_id}/assets")
    assert inventory_response.status_code == 200
    assert inventory_response.json()["summary"]["total_assets"] == 1


@pytest.mark.asyncio
async def test_sync_cluster_persists_snapshot_row(inventory_client):
    create_response = inventory_client["client"].post(
        "/api/v1/clusters",
        json={
            "name": "prod",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
            "aws_region": "ap-northeast-2",
        },
        headers=USER_HEADERS,
    )
    cluster_id = create_response.json()["id"]

    inventory_client["client"].post(f"/api/v1/clusters/{cluster_id}/sync")

    async with inventory_client["sessionmaker"]() as session:
        snapshot = await session.scalar(select(InventorySnapshot).where(InventorySnapshot.cluster_id == cluster_id))

    assert snapshot is not None
    assert snapshot.scan_id == "scan-123"
    assert snapshot.raw_result_json["s3_buckets"][0]["name"] == "bucket-a"


def test_sync_nonexistent_cluster_returns_404(inventory_client):
    response = inventory_client["client"].post("/api/v1/clusters/missing/sync")

    assert response.status_code == 404
    assert response.json()["detail"] == "Cluster not found"


@pytest.mark.asyncio
async def test_sync_cluster_missing_aws_config_returns_400(inventory_client):
    create_response = inventory_client["client"].post(
        "/api/v1/clusters",
        json={
            "name": "prod",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
            "aws_region": "ap-northeast-2",
        },
        headers=USER_HEADERS,
    )
    cluster_id = create_response.json()["id"]

    async with inventory_client["sessionmaker"]() as session:
        cluster = await session.scalar(select(Cluster).where(Cluster.id == cluster_id))
        cluster.aws_role_arn = ""
        await session.commit()

    response = inventory_client["client"].post(f"/api/v1/clusters/{cluster_id}/sync")

    assert response.status_code == 400
    assert "missing AWS discovery configuration" in response.json()["detail"]


def test_sync_response_matches_schema_shape(inventory_client):
    create_response = inventory_client["client"].post(
        "/api/v1/clusters",
        json={
            "name": "prod",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
            "aws_region": "ap-northeast-2",
        },
        headers=USER_HEADERS,
    )
    cluster_id = create_response.json()["id"]

    response = inventory_client["client"].post(f"/api/v1/clusters/{cluster_id}/sync")

    assert response.status_code == 200
    assert set(response.json().keys()) == {"status", "cluster_id", "scan_id"}
