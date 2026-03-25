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
from app.gateway.models import InventorySnapshot
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.main import app

USER_HEADERS = {"X-User-Id": "user-1"}


@pytest.fixture
async def inventory_client(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "inventory_api.sqlite3"
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
            "iam_roles": [{"name": "role-a"}],
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
        create_response = client.post(
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
        client.post(f"/api/v1/clusters/{cluster_id}/sync")
        yield {"client": client, "cluster_id": cluster_id, "sessionmaker": sessionmaker}
    app.dependency_overrides.clear()
    await engine.dispose()


def test_get_cluster_assets_reads_latest_snapshot(inventory_client):
    response = inventory_client["client"].get(f"/api/v1/clusters/{inventory_client['cluster_id']}/assets")

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_assets"] == 2
    assert {asset["asset_id"] for asset in body["assets"]} == {"iam-role:role-a", "s3:bucket-a"}
    s3_asset = next(asset for asset in body["assets"] if asset["asset_id"] == "s3:bucket-a")
    assert s3_asset["status"] == {"discovered": True, "source": "aws"}
    assert s3_asset["cluster_id"] == inventory_client["cluster_id"]
    assert s3_asset["details"]["arn"] == "arn:aws:s3:::bucket-a"


def test_get_asset_detail_reads_one_asset_from_latest_snapshot(inventory_client):
    response = inventory_client["client"].get("/api/v1/assets/s3:bucket-a")

    assert response.status_code == 200
    body = response.json()
    assert body["asset_id"] == "s3:bucket-a"
    assert body["asset_type"] == "s3"
    assert body["details"]["arn"] == "arn:aws:s3:::bucket-a"


def test_get_cluster_assets_returns_empty_when_no_snapshot_exists(inventory_client):
    response = inventory_client["client"].post(
        "/api/v1/clusters",
        json={
            "name": "empty",
            "aws_account_id": "999999999999",
            "aws_role_arn": "arn:aws:iam::999999999999:role/discovery",
            "aws_region": "us-west-2",
        },
        headers=USER_HEADERS,
    )
    cluster_id = response.json()["id"]

    assets_response = inventory_client["client"].get(f"/api/v1/clusters/{cluster_id}/assets")

    assert assets_response.status_code == 200
    assert assets_response.json() == {"summary": {"total_assets": 0}, "assets": []}


def test_get_cluster_assets_for_nonexistent_cluster_returns_404(inventory_client):
    response = inventory_client["client"].get("/api/v1/clusters/missing/assets")

    assert response.status_code == 404
    assert response.json()["detail"] == "Cluster not found"


def test_get_asset_detail_not_found_returns_404(inventory_client):
    response = inventory_client["client"].get("/api/v1/assets/missing-asset")

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


@pytest.mark.asyncio
async def test_latest_snapshot_behavior_uses_newest_snapshot(inventory_client):
    async with inventory_client["sessionmaker"]() as session:
        latest = await session.scalar(
            select(InventorySnapshot)
            .where(InventorySnapshot.cluster_id == inventory_client["cluster_id"])
        )
        latest.raw_result_json = {
            "scan_id": "scan-999",
            "aws_account_id": "123456789012",
            "region": "ap-northeast-2",
            "scanned_at": "2026-03-19T13:00:00+00:00",
            "iam_roles": [],
            "iam_users": [],
            "s3_buckets": [{"name": "bucket-new", "arn": "arn:aws:s3:::bucket-new"}],
            "rds_instances": [],
            "ec2_instances": [],
        }
        await session.commit()

        newer_snapshot = InventorySnapshot(
            cluster_id=inventory_client["cluster_id"],
            scan_id="scan-124",
            scanned_at=latest.scanned_at.replace(hour=13),
            raw_result_json=latest.raw_result_json,
        )
        session.add(newer_snapshot)
        await session.commit()

    response = inventory_client["client"].get(f"/api/v1/clusters/{inventory_client['cluster_id']}/assets")

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_assets"] == 1
    assert body["assets"][0]["asset_id"] == "s3:bucket-new"


def test_assets_list_response_matches_schema_shape(inventory_client):
    response = inventory_client["client"].get(f"/api/v1/clusters/{inventory_client['cluster_id']}/assets")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"summary", "assets"}
    assert set(body["summary"].keys()) == {"total_assets"}
    assert {"asset_id", "asset_type", "name", "cluster_id", "cluster_name", "account_id", "region", "status", "details"} <= set(
        body["assets"][0].keys()
    )


def test_empty_result_payload_after_sync_maps_to_empty_assets(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "inventory_api_empty.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    import asyncio
    asyncio.run(_setup())

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(inventory_service_module, "assume_role", lambda role_arn: f"session-for:{role_arn}")
    monkeypatch.setattr(
        inventory_service_module,
        "collect_all_assets",
        lambda session, account_id, region: {
            "scan_id": "scan-empty",
            "aws_account_id": account_id,
            "region": region,
            "scanned_at": "2026-03-19T12:00:00+00:00",
            "iam_roles": [],
            "iam_users": [],
            "s3_buckets": [],
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
        create_response = client.post(
            "/api/v1/clusters",
            json={
                "name": "empty",
                "aws_account_id": "123456789012",
                "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
                "aws_region": "ap-northeast-2",
            },
            headers=USER_HEADERS,
        )
        cluster_id = create_response.json()["id"]
        client.post(f"/api/v1/clusters/{cluster_id}/sync")
        response = client.get(f"/api/v1/clusters/{cluster_id}/assets")
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())

    assert response.status_code == 200
    assert response.json() == {"summary": {"total_assets": 0}, "assets": []}
