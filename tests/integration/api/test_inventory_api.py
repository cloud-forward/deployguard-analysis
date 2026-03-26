from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.application.services.inventory_service as inventory_service_module
from app.application.di import get_auth_service, get_cluster_service, get_inventory_service, get_inventory_view_service
from app.application.services.auth_service import AuthService
from app.application.services.cluster_service import ClusterService
from app.application.services.inventory_service import InventoryService
from app.application.services.inventory_view_service import InventoryViewService
from app.gateway.db.base import Base
from app.gateway.models import InventorySnapshot
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.main import app
from app.security.passwords import hash_password


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    name: str | None = None
    is_active: bool = True


class FakeUserRepository:
    def __init__(self, users: list[FakeUser]):
        self._by_email = {user.email: user for user in users}
        self._by_id = {user.id: user for user in users}

    async def get_by_email(self, email: str):
        return self._by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._by_id.get(user_id)


def _auth_headers(client: TestClient, user_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


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

    async def override_get_inventory_view_service():
        async with sessionmaker() as session:
            yield InventoryViewService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                scan_repository=SQLAlchemyScanRepository(session),
                snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
                db=session,
            )

    async def override_get_cluster_service():
        async with sessionmaker() as session:
            yield ClusterService(cluster_repository=SQLAlchemyClusterRepository(session))

    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )

    app.dependency_overrides[get_inventory_service] = override_get_inventory_service
    app.dependency_overrides[get_inventory_view_service] = override_get_inventory_view_service
    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/clusters",
            json={
                "name": "prod",
                "aws_account_id": "123456789012",
                "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
                "aws_region": "ap-northeast-2",
            },
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_response.json()["id"]
        client.post(
            f"/api/v1/clusters/{cluster_id}/sync",
            headers=_auth_headers(client, "user-1"),
        )
        yield {"client": client, "cluster_id": cluster_id, "sessionmaker": sessionmaker}
    app.dependency_overrides.clear()
    await engine.dispose()


def test_get_cluster_assets_reads_latest_snapshot(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/assets",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_assets"] == 2
    assert {asset["asset_id"] for asset in body["assets"]} == {"iam-role:role-a", "s3:bucket-a"}
    s3_asset = next(asset for asset in body["assets"] if asset["asset_id"] == "s3:bucket-a")
    assert s3_asset["status"] == {"discovered": True, "source": "aws"}
    assert s3_asset["cluster_id"] == inventory_client["cluster_id"]
    assert s3_asset["details"]["arn"] == "arn:aws:s3:::bucket-a"


def test_get_asset_detail_reads_one_asset_from_latest_snapshot(inventory_client):
    response = inventory_client["client"].get(
        "/api/v1/assets/s3:bucket-a",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

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
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )
    cluster_id = response.json()["id"]

    assets_response = inventory_client["client"].get(
        f"/api/v1/clusters/{cluster_id}/assets",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert assets_response.status_code == 200
    assert assets_response.json() == {"summary": {"total_assets": 0}, "assets": []}


def test_get_cluster_assets_for_nonexistent_cluster_returns_404(inventory_client):
    response = inventory_client["client"].get(
        "/api/v1/clusters/missing/assets",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Cluster not found"


def test_get_asset_detail_not_found_returns_404(inventory_client):
    response = inventory_client["client"].get(
        "/api/v1/assets/missing-asset",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

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

    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/assets",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_assets"] == 1
    assert body["assets"][0]["asset_id"] == "s3:bucket-new"


def test_assets_list_response_matches_schema_shape(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/assets",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"summary", "assets"}
    assert set(body["summary"].keys()) == {"total_assets"}
    assert {"asset_id", "asset_type", "name", "cluster_id", "cluster_name", "account_id", "region", "status", "details"} <= set(
        body["assets"][0].keys()
    )


def test_inventory_routes_require_jwt_and_ignore_x_user_id_only(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/assets",
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 401


def test_inventory_assets_not_visible_to_other_user(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/assets",
        headers=_auth_headers(inventory_client["client"], "user-2"),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Cluster not found"


def test_inventory_summary_uses_owned_cluster_only(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/inventory/summary",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == inventory_client["cluster_id"]
    assert body["cluster_name"] == "prod"
    assert body["total_node_count"] == 2


def test_inventory_summary_not_visible_to_other_user(inventory_client):
    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/inventory/summary",
        headers=_auth_headers(inventory_client["client"], "user-2"),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Cluster not found"


@pytest.mark.asyncio
async def test_inventory_summary_allows_legacy_cluster_with_null_owner(inventory_client):
    legacy_cluster_id = "legacy-null-owner-cluster"
    async with inventory_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (
                    id, user_id, name, cluster_type, aws_account_id, aws_region, created_at, updated_at
                )
                VALUES (
                    :cluster_id, NULL, 'legacy-cluster', 'aws', '123456789012', 'ap-northeast-2',
                    '2026-03-24 10:00:00', '2026-03-24 10:00:00'
                )
                """
            ),
            {"cluster_id": legacy_cluster_id},
        )
        session.add(
            InventorySnapshot(
                cluster_id=legacy_cluster_id,
                scan_id="legacy-scan",
                scanned_at=datetime.fromisoformat("2026-03-24T10:05:00+00:00"),
                raw_result_json={
                    "iam_roles": [{"name": "legacy-role"}],
                    "iam_users": [],
                    "s3_buckets": [],
                    "rds_instances": [],
                    "ec2_instances": [],
                },
            )
        )
        await session.commit()

    response = inventory_client["client"].get(
        f"/api/v1/clusters/{legacy_cluster_id}/inventory/summary",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == legacy_cluster_id
    assert body["total_node_count"] == 1
    assert body["aws_resources"] == {"iam_role": 1}


@pytest.mark.asyncio
async def test_inventory_scanner_status_allows_legacy_cluster_with_null_owner(inventory_client):
    legacy_cluster_id = "legacy-null-owner-eks"
    async with inventory_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (
                    id, user_id, name, cluster_type, created_at, updated_at
                )
                VALUES (
                    :cluster_id, NULL, 'legacy-eks', 'eks',
                    '2026-03-24 10:00:00', '2026-03-24 10:00:00'
                )
                """
            ),
            {"cluster_id": legacy_cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO scan_records (
                    id, user_id, scan_id, cluster_id, scanner_type, status, s3_keys,
                    requested_at, request_source, created_at, completed_at
                )
                VALUES
                    ('legacy-scan-row', NULL, 'legacy-k8s-scan', :cluster_id, 'k8s', 'completed', '[]',
                     '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:10:00')
                """
            ),
            {"cluster_id": legacy_cluster_id},
        )
        await session.commit()

    response = inventory_client["client"].get(
        f"/api/v1/clusters/{legacy_cluster_id}/inventory/scanner-status",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert [item["scanner_type"] for item in body["scanners"]] == ["k8s", "image"]
    k8s_item = next(item for item in body["scanners"] if item["scanner_type"] == "k8s")
    image_item = next(item for item in body["scanners"] if item["scanner_type"] == "image")
    assert k8s_item["status"] == "active"
    assert k8s_item["coverage_status"] == "covered"
    assert image_item["status"] == "inactive"
    assert image_item["coverage_status"] == "not_covered"


@pytest.mark.asyncio
async def test_inventory_summary_prefers_latest_completed_graph_by_completed_at(inventory_client):
    async with inventory_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, status, node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES
                    ('graph-older-created', :cluster_id, 'completed', 1, 0, 1, 0, '2026-03-24 12:00:00', '2026-03-24 13:00:00'),
                    ('graph-newer-completed', :cluster_id, 'completed', 2, 0, 0, 1, '2026-03-24 14:00:00', '2026-03-24 12:00:00')
                """
            ),
            {"cluster_id": inventory_client["cluster_id"]},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    id, graph_id, node_id, node_type, namespace, base_risk, is_entry_point, is_crown_jewel, metadata
                )
                VALUES
                    ('gn-1', 'graph-older-created', 'pod:prod/old', 'pod', 'prod', 0.9, TRUE, FALSE, '{}'),
                    ('gn-2', 'graph-newer-completed', 'pod:prod/api', 'pod', 'prod', 0.4, FALSE, FALSE, '{}'),
                    ('gn-3', 'graph-newer-completed', 'service:prod/api', 'service', 'prod', 0.2, FALSE, TRUE, '{}')
                """
            )
        )
        await session.commit()

    response = inventory_client["client"].get(
        f"/api/v1/clusters/{inventory_client['cluster_id']}/inventory/summary",
        headers=_auth_headers(inventory_client["client"], "user-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_node_count"] == 2
    assert body["k8s_resources"] == {"pod": 1, "service": 1}
    assert body["risk_summary"]["entry_point_count"] == 0
    assert body["risk_summary"]["crown_jewel_count"] == 1


@pytest.mark.asyncio
async def test_inventory_scanner_status_uses_applicable_scanners_and_latest_scan_activity(tmp_path: Path):
    db_path = tmp_path / "inventory_scanner_status.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    await _setup()

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_inventory_service():
        async with sessionmaker() as session:
            yield InventoryService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                inventory_snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
            )

    async def override_get_inventory_view_service():
        async with sessionmaker() as session:
            yield InventoryViewService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                scan_repository=SQLAlchemyScanRepository(session),
                snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
                db=session,
            )

    async def override_get_cluster_service():
        async with sessionmaker() as session:
            yield ClusterService(cluster_repository=SQLAlchemyClusterRepository(session))

    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password"))]
        )
    )

    app.dependency_overrides[get_inventory_service] = override_get_inventory_service
    app.dependency_overrides[get_inventory_view_service] = override_get_inventory_view_service
    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/clusters",
            json={"name": "eks-cluster", "cluster_type": "eks"},
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_response.json()["id"]

        async def _seed():
            async with sessionmaker() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO scan_records (
                            id, user_id, scan_id, cluster_id, scanner_type, status, s3_keys,
                            requested_at, request_source, created_at, completed_at
                        )
                        VALUES
                            ('scan-1', 'user-1', 'k8s-created', :cluster_id, 'k8s', 'created', '[]',
                             '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', NULL),
                            ('scan-2', 'user-1', 'image-completed-old-create', :cluster_id, 'image', 'completed', '[]',
                             '2026-03-24 09:00:00', 'manual', '2026-03-24 12:00:00', '2026-03-24 13:00:00'),
                            ('scan-3', 'user-1', 'image-completed-new-completion', :cluster_id, 'image', 'completed', '[]',
                             '2026-03-24 08:00:00', 'manual', '2026-03-24 11:00:00', '2026-03-24 14:00:00')
                        """
                    ),
                    {"cluster_id": cluster_id},
                )
                await session.commit()

        await _seed()

        response = client.get(
            f"/api/v1/clusters/{cluster_id}/inventory/scanner-status",
            headers=_auth_headers(client, "user-1"),
        )

    app.dependency_overrides.clear()
    await engine.dispose()

    assert response.status_code == 200
    body = response.json()
    assert [item["scanner_type"] for item in body["scanners"]] == ["k8s", "image"]

    k8s_item = next(item for item in body["scanners"] if item["scanner_type"] == "k8s")
    image_item = next(item for item in body["scanners"] if item["scanner_type"] == "image")

    assert k8s_item["status"] == "active"
    assert k8s_item["coverage_status"] == "not_covered"
    assert k8s_item["scan_id"] == "k8s-created"

    assert image_item["status"] == "active"
    assert image_item["coverage_status"] == "covered"
    assert image_item["scan_id"] == "image-completed-new-completion"


@pytest.mark.asyncio
async def test_inventory_assets_falls_back_to_latest_graph_with_nodes_when_no_completed_graph(tmp_path: Path):
    db_path = tmp_path / "inventory_graph_fallback.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    await _setup()

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_inventory_service():
        async with sessionmaker() as session:
            yield InventoryService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                inventory_snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
            )

    async def override_get_inventory_view_service():
        async with sessionmaker() as session:
            yield InventoryViewService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                scan_repository=SQLAlchemyScanRepository(session),
                snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
                db=session,
            )

    async def override_get_cluster_service():
        async with sessionmaker() as session:
            yield ClusterService(cluster_repository=SQLAlchemyClusterRepository(session))

    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password"))]
        )
    )

    app.dependency_overrides[get_inventory_service] = override_get_inventory_service
    app.dependency_overrides[get_inventory_view_service] = override_get_inventory_view_service
    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/clusters",
            json={"name": "self-cluster", "cluster_type": "self-managed"},
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_response.json()["id"]

        async def _seed():
            async with sessionmaker() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO graph_snapshots (
                            id, cluster_id, status, node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                        )
                        VALUES
                            ('graph-pending', :cluster_id, 'pending', 2, 0, 1, 0, NULL, '2026-03-24 15:00:00')
                        """
                    ),
                    {"cluster_id": cluster_id},
                )
                await session.execute(
                    text(
                        """
                        INSERT INTO graph_nodes (
                            id, graph_id, node_id, node_type, namespace, base_risk, is_entry_point, is_crown_jewel, metadata
                        )
                        VALUES
                            ('fallback-1', 'graph-pending', 'pod:prod/web', 'pod', 'prod', 0.8, TRUE, FALSE, '{}'),
                            ('fallback-2', 'graph-pending', 'service:prod/web', 'service', 'prod', 0.3, FALSE, FALSE, '{}')
                        """
                    )
                )
                await session.commit()

        await _seed()

        response = client.get(
            f"/api/v1/clusters/{cluster_id}/inventory/assets",
            headers=_auth_headers(client, "user-1"),
        )

    app.dependency_overrides.clear()
    await engine.dispose()

    assert response.status_code == 200
    body = response.json()
    assert body["graph_id"] == "graph-pending"
    assert body["total_count"] == 2
    assert [asset["node_id"] for asset in body["assets"]] == ["pod:prod/web", "service:prod/web"]


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

    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password"))]
        )
    )

    async def override_get_inventory_view_service():
        async with sessionmaker() as session:
            yield InventoryViewService(
                cluster_repository=SQLAlchemyClusterRepository(session),
                scan_repository=SQLAlchemyScanRepository(session),
                snapshot_repository=SQLAlchemyInventorySnapshotRepository(session),
                db=session,
            )

    app.dependency_overrides[get_inventory_service] = override_get_inventory_service
    app.dependency_overrides[get_inventory_view_service] = override_get_inventory_view_service
    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/clusters",
            json={
                "name": "empty",
                "aws_account_id": "123456789012",
                "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
                "aws_region": "ap-northeast-2",
            },
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_response.json()["id"]
        client.post(
            f"/api/v1/clusters/{cluster_id}/sync",
            headers=_auth_headers(client, "user-1"),
        )
        response = client.get(
            f"/api/v1/clusters/{cluster_id}/assets",
            headers=_auth_headers(client, "user-1"),
        )
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())

    assert response.status_code == 200
    assert response.json() == {"summary": {"total_assets": 0}, "assets": []}
