from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.di import get_auth_service, get_inventory_view_service, get_user_overview_service
from app.application.services.auth_service import AuthService
from app.application.services.inventory_view_service import InventoryViewService
from app.application.services.user_overview_service import UserOverviewService
from app.gateway.db.base import Base
from app.gateway.models import GraphNode, InventorySnapshot
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.gateway.repositories.inventory_snapshot_repository import SQLAlchemyInventorySnapshotRepository
from app.gateway.repositories.scan_repository import SQLAlchemyScanRepository
from app.gateway.repositories.user_overview_repository import SQLAlchemyUserOverviewRepository
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


@pytest.fixture
async def overview_client(tmp_path):
    db_path = tmp_path / "me_overview_api.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_user_overview_service():
        async with sessionmaker() as session:
            yield UserOverviewService(
                overview_repository=SQLAlchemyUserOverviewRepository(session=session),
            )

    async def override_get_inventory_view_service():
        async with sessionmaker() as session:
            yield InventoryViewService(
                cluster_repository=SQLAlchemyClusterRepository(session=session),
                scan_repository=SQLAlchemyScanRepository(session=session),
                snapshot_repository=SQLAlchemyInventorySnapshotRepository(session=session),
                db=session,
            )

    app.dependency_overrides[get_user_overview_service] = override_get_user_overview_service
    app.dependency_overrides[get_inventory_view_service] = override_get_inventory_view_service
    app.dependency_overrides[get_auth_service] = lambda: AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-3", email="user-3@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )

    with TestClient(app) as client:
        yield {"client": client, "sessionmaker": sessionmaker}

    app.dependency_overrides.clear()
    await engine.dispose()


def _auth_headers(client: TestClient, user_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _seed_overview_data(sessionmaker) -> None:
    async with sessionmaker() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, user_id, name, cluster_type, aws_account_id, aws_region, created_at, updated_at)
                VALUES
                    ('c-eks-u1', 'user-1', 'user1-eks', 'eks', NULL, NULL, '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-self-u1', 'user-1', 'user1-self', 'self-managed', NULL, NULL, '2026-03-24 11:00:00', '2026-03-24 11:00:00'),
                    ('c-aws-u1', 'user-1', 'user1-aws', 'aws', '111111111111', 'us-west-2', '2026-03-24 12:00:00', '2026-03-24 12:00:00'),
                    ('c-eks-u2', 'user-2', 'user2-eks', 'eks', NULL, NULL, '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-aws-u2', 'user-2', 'user2-aws', 'aws', '222222222222', 'ap-northeast-2', '2026-03-24 10:00:00', '2026-03-24 10:00:00')
                """
            )
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status,
                    node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES
                    ('g-u1-a', 'c-eks-u1', 'k1', NULL, NULL, 'completed', 0, 0, 0, 0, '2026-03-24 10:05:00', '2026-03-24 10:00:00'),
                    ('g-u1-b', 'c-self-u1', 'k2', NULL, NULL, 'completed', 0, 0, 0, 0, '2026-03-24 10:05:00', '2026-03-24 10:00:00'),
                    ('g-u2-a', 'c-eks-u2', 'k3', NULL, NULL, 'completed', 0, 0, 0, 0, '2026-03-24 10:05:00', '2026-03-24 10:00:00')
                """
            )
        )
        session.add_all(
            [
                GraphNode(
                    id="gn-u1-1",
                    graph_id="g-u1-a",
                    node_id="pod:prod/api-5d6f",
                    node_type="pod",
                    label="api-5d6f",
                    risk_level="critical",
                    namespace="prod",
                    base_risk=0.9,
                    has_runtime_evidence=None,
                    is_entry_point=True,
                    is_crown_jewel=False,
                    metadata_json={"name": "api-5d6f", "is_public": True},
                ),
                GraphNode(
                    id="gn-u1-2",
                    graph_id="g-u1-a",
                    node_id="service:prod/api-svc",
                    node_type="service",
                    label="api-svc",
                    risk_level="medium",
                    namespace="prod",
                    base_risk=0.5,
                    has_runtime_evidence=None,
                    is_entry_point=False,
                    is_crown_jewel=True,
                    metadata_json={"name": "api-svc"},
                ),
                GraphNode(
                    id="gn-u1-3",
                    graph_id="g-u1-b",
                    node_id="service_account:ops/deployer",
                    node_type="service_account",
                    label="deployer",
                    risk_level="low",
                    namespace="ops",
                    base_risk=0.2,
                    has_runtime_evidence=None,
                    is_entry_point=False,
                    is_crown_jewel=False,
                    metadata_json={"name": "deployer"},
                ),
                GraphNode(
                    id="gn-u2-1",
                    graph_id="g-u2-a",
                    node_id="pod:default/user2-pod",
                    node_type="pod",
                    label="user2-pod",
                    risk_level="high",
                    namespace="default",
                    base_risk=0.8,
                    has_runtime_evidence=None,
                    is_entry_point=True,
                    is_crown_jewel=False,
                    metadata_json={"name": "user2-pod", "is_public": False},
                ),
                InventorySnapshot(
                    id="snap-u1-aws",
                    cluster_id="c-aws-u1",
                    scan_id="inv-u1-aws",
                    scanned_at=datetime.fromisoformat("2026-03-24T12:30:00"),
                    created_at=datetime.fromisoformat("2026-03-24T12:30:00"),
                    raw_result_json={
                        "s3_buckets": [
                            {
                                "name": "u1-public-bucket",
                                "arn": "arn:aws:s3:::u1-public-bucket",
                                "public_access_block": {
                                    "block_public_acls": True,
                                    "ignore_public_acls": True,
                                    "block_public_policy": True,
                                    "restrict_public_buckets": True,
                                },
                            }
                        ],
                        "rds_instances": [
                            {
                                "identifier": "u1-db",
                                "arn": "arn:aws:rds:us-west-2:111111111111:db:u1-db",
                                "publicly_accessible": True,
                                "engine": "postgres",
                            }
                        ],
                    },
                ),
                InventorySnapshot(
                    id="snap-u2-aws",
                    cluster_id="c-aws-u2",
                    scan_id="inv-u2-aws",
                    scanned_at=datetime.fromisoformat("2026-03-24T12:30:00"),
                    created_at=datetime.fromisoformat("2026-03-24T12:30:00"),
                    raw_result_json={
                        "iam_users": [
                            {
                                "username": "user2-admin",
                                "arn": "arn:aws:iam::222222222222:user/user2-admin",
                                "has_mfa": False,
                            }
                        ]
                    },
                ),
            ]
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, expected_scans, created_at
                )
                VALUES
                    ('job-u1-a', 'user-1', 'c-eks-u1', 'g-u1-a', 'completed', '[]', '2026-03-24 10:00:00'),
                    ('job-u1-b', 'user-1', 'c-self-u1', 'g-u1-b', 'running', '[]', '2026-03-24 10:00:00'),
                    ('job-u1-c', 'user-1', 'c-self-u1', NULL, 'failed', '[]', '2026-03-24 13:00:00'),
                    ('job-u2-a', 'user-2', 'c-eks-u2', 'g-u2-a', 'completed', '[]', '2026-03-24 10:00:00')
                """
            )
        )
        await session.execute(
            text(
                """
                INSERT INTO scan_records (
                    id, user_id, scan_id, cluster_id, scanner_type, status, s3_keys, requested_at, request_source, created_at, completed_at
                )
                VALUES
                    ('scan-row-1', 'user-1', 'scan-u1-1', 'c-eks-u1', 'k8s', 'completed', '[]', '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:01:00'),
                    ('scan-row-2', 'user-1', 'scan-u1-2', 'c-self-u1', 'image', 'completed', '[]', '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:01:00'),
                    ('scan-row-3', 'user-1', 'scan-u1-3', 'c-aws-u1', 'aws', 'completed', '[]', '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:01:00'),
                    ('scan-row-6', 'user-1', 'scan-u1-4', 'c-aws-u1', 'aws', 'failed', '[]', '2026-03-24 14:00:00', 'manual', '2026-03-24 14:00:00', '2026-03-24 14:01:00'),
                    ('scan-row-4', 'user-2', 'scan-u2-1', 'c-eks-u2', 'k8s', 'completed', '[]', '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:01:00'),
                    ('scan-row-5', 'user-2', 'scan-u2-2', 'c-aws-u2', 'aws', 'completed', '[]', '2026-03-24 10:00:00', 'manual', '2026-03-24 10:00:00', '2026-03-24 10:01:00')
                """
            )
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk, hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES
                    ('path-u1-1', 'g-u1-a', 'u1-path-1', 'high', 0.9, 0.9, 2, 'e1', 't1', '["e1","m1","t1"]'),
                    ('path-u1-2', 'g-u1-a', 'u1-path-2', 'medium', 0.5, 0.5, 1, 'e2', 't2', '["e2","t2"]'),
                    ('path-u1-3', 'g-u1-b', 'u1-path-3', 'low', 0.2, 0.2, 1, 'e3', 't3', '["e3","t3"]'),
                    ('path-u2-1', 'g-u2-a', 'u2-path-1', 'critical', 1.0, 1.0, 3, 'e4', 't4', '["e4","m4","m5","t4"]')
                """
            )
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    id, graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata
                )
                VALUES
                    ('rec-u1-1', 'g-u1-a', 'u1-rec-1', 0, 'a', 'b', 'x', 'fix-a', 'desc-a', '[]', '[]', 1.0, 0.4, 0.4, 0.4, '{}'),
                    ('rec-u1-2', 'g-u1-b', 'u1-rec-2', 0, 'c', 'd', 'y', 'fix-b', 'desc-b', '[]', '[]', 2.0, 0.3, 0.3, 0.7, '{}'),
                    ('rec-u1-3', 'g-u1-b', 'u1-rec-3', 1, 'e', 'f', 'z', 'fix-c', 'desc-c', '[]', '[]', 3.0, 0.2, 0.2, 0.9, '{}'),
                    ('rec-u2-1', 'g-u2-a', 'u2-rec-1', 0, 'g', 'h', 'q', 'fix-d', 'desc-d', '[]', '[]', 4.0, 0.1, 0.1, 1.0, '{}')
                """
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_me_overview_requires_jwt(overview_client):
    response = overview_client["client"].get("/api/v1/me/overview")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_overview_returns_asset_centered_summary_for_authenticated_user(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-1"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_assets": 5,
        "k8s_assets": 3,
        "aws_assets": 2,
        "public_assets": 2,
        "entry_point_assets": 1,
        "crown_jewel_assets": 1,
    }


@pytest.mark.asyncio
async def test_me_overview_excludes_another_users_assets(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-2"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_assets": 2,
        "k8s_assets": 1,
        "aws_assets": 1,
        "public_assets": 0,
        "entry_point_assets": 1,
        "crown_jewel_assets": 0,
    }


@pytest.mark.asyncio
async def test_me_overview_returns_zeros_for_user_with_no_data(overview_client):
    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-3"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_assets": 0,
        "k8s_assets": 0,
        "aws_assets": 0,
        "public_assets": 0,
        "entry_point_assets": 0,
        "crown_jewel_assets": 0,
    }


@pytest.mark.asyncio
async def test_me_assets_requires_jwt(overview_client):
    response = overview_client["client"].get("/api/v1/me/assets")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_assets_returns_unified_inventory_assets_for_authenticated_user(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/assets",
        headers=_auth_headers(overview_client["client"], "user-1"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "asset_id": "pod:prod/api-5d6f",
                "asset_type": "pod",
                "asset_domain": "k8s",
                "name": "api-5d6f",
                "cluster_id": "c-eks-u1",
                "cluster_name": "user1-eks",
                "aws_account_id": None,
                "aws_region": None,
                "base_risk": 0.9,
                "is_public": True,
                "is_entry_point": True,
                "is_crown_jewel": False,
            },
            {
                "asset_id": "service:prod/api-svc",
                "asset_type": "service",
                "asset_domain": "k8s",
                "name": "api-svc",
                "cluster_id": "c-eks-u1",
                "cluster_name": "user1-eks",
                "aws_account_id": None,
                "aws_region": None,
                "base_risk": 0.5,
                "is_public": None,
                "is_entry_point": False,
                "is_crown_jewel": True,
            },
            {
                "asset_id": "service_account:ops/deployer",
                "asset_type": "service_account",
                "asset_domain": "k8s",
                "name": "deployer",
                "cluster_id": "c-self-u1",
                "cluster_name": "user1-self",
                "aws_account_id": None,
                "aws_region": None,
                "base_risk": 0.2,
                "is_public": None,
                "is_entry_point": False,
                "is_crown_jewel": False,
            },
            {
                "asset_id": "s3:u1-public-bucket",
                "asset_type": "s3",
                "asset_domain": "aws",
                "name": "u1-public-bucket",
                "cluster_id": "c-aws-u1",
                "cluster_name": "user1-aws",
                "aws_account_id": "111111111111",
                "aws_region": None,
                "base_risk": None,
                "is_public": False,
                "is_entry_point": None,
                "is_crown_jewel": None,
            },
            {
                "asset_id": "rds:u1-db",
                "asset_type": "rds",
                "asset_domain": "aws",
                "name": "u1-db",
                "cluster_id": "c-aws-u1",
                "cluster_name": "user1-aws",
                "aws_account_id": "111111111111",
                "aws_region": "us-west-2",
                "base_risk": None,
                "is_public": True,
                "is_entry_point": None,
                "is_crown_jewel": None,
            },
        ],
        "total": 5,
    }


@pytest.mark.asyncio
async def test_me_assets_excludes_another_users_clusters_and_returns_owned_inventory_only(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/assets",
        headers=_auth_headers(overview_client["client"], "user-2"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "asset_id": "pod:default/user2-pod",
                "asset_type": "pod",
                "asset_domain": "k8s",
                "name": "user2-pod",
                "cluster_id": "c-eks-u2",
                "cluster_name": "user2-eks",
                "aws_account_id": None,
                "aws_region": None,
                "base_risk": 0.8,
                "is_public": False,
                "is_entry_point": True,
                "is_crown_jewel": False,
            },
            {
                "asset_id": "iam-user:user2-admin",
                "asset_type": "iam_user",
                "asset_domain": "aws",
                "name": "user2-admin",
                "cluster_id": "c-aws-u2",
                "cluster_name": "user2-aws",
                "aws_account_id": "222222222222",
                "aws_region": None,
                "base_risk": None,
                "is_public": None,
                "is_entry_point": None,
                "is_crown_jewel": None,
            },
        ],
        "total": 2,
    }


@pytest.mark.asyncio
async def test_me_assets_returns_empty_list_for_user_with_no_data(overview_client):
    response = overview_client["client"].get(
        "/api/v1/me/assets",
        headers=_auth_headers(overview_client["client"], "user-3"),
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


@pytest.mark.asyncio
async def test_me_groups_requires_jwt(overview_client):
    response = overview_client["client"].get("/api/v1/me/groups")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_groups_returns_only_authenticated_users_computed_groups(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/groups",
        headers=_auth_headers(overview_client["client"], "user-1"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "group_key": "aws_account_id:null|asset_domain:k8s",
                "aws_account_id": None,
                "asset_domain": "k8s",
                "total_assets": 3,
                "k8s_assets": 3,
                "aws_assets": 0,
                "public_assets": 1,
                "entry_point_assets": 1,
                "crown_jewel_assets": 1,
            },
            {
                "group_key": "aws_account_id:111111111111|asset_domain:aws",
                "aws_account_id": "111111111111",
                "asset_domain": "aws",
                "total_assets": 2,
                "k8s_assets": 0,
                "aws_assets": 2,
                "public_assets": 1,
                "entry_point_assets": 0,
                "crown_jewel_assets": 0,
            },
        ],
        "total": 2,
    }


@pytest.mark.asyncio
async def test_me_groups_excludes_another_users_assets_and_groups_inventory_only(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/groups",
        headers=_auth_headers(overview_client["client"], "user-2"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "group_key": "aws_account_id:null|asset_domain:k8s",
                "aws_account_id": None,
                "asset_domain": "k8s",
                "total_assets": 1,
                "k8s_assets": 1,
                "aws_assets": 0,
                "public_assets": 0,
                "entry_point_assets": 1,
                "crown_jewel_assets": 0,
            },
            {
                "group_key": "aws_account_id:222222222222|asset_domain:aws",
                "aws_account_id": "222222222222",
                "asset_domain": "aws",
                "total_assets": 1,
                "k8s_assets": 0,
                "aws_assets": 1,
                "public_assets": 0,
                "entry_point_assets": 0,
                "crown_jewel_assets": 0,
            },
        ],
        "total": 2,
    }


@pytest.mark.asyncio
async def test_me_groups_returns_empty_list_for_user_with_no_data(overview_client):
    response = overview_client["client"].get(
        "/api/v1/me/groups",
        headers=_auth_headers(overview_client["client"], "user-3"),
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}
