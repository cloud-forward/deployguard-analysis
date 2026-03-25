from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.di import get_auth_service, get_user_overview_service
from app.application.services.auth_service import AuthService
from app.application.services.user_overview_service import UserOverviewService
from app.gateway.db.base import Base
from app.gateway.repositories.user_overview_repository import SQLAlchemyUserOverviewRepository
from app.main import app
from app.security.passwords import hash_password


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

    app.dependency_overrides[get_user_overview_service] = override_get_user_overview_service
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
                INSERT INTO clusters (id, user_id, name, cluster_type, created_at, updated_at)
                VALUES
                    ('c-eks-u1', 'user-1', 'user1-eks', 'eks', '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-self-u1', 'user-1', 'user1-self', 'self-managed', '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-aws-u1', 'user-1', 'user1-aws', 'aws', '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-eks-u2', 'user-2', 'user2-eks', 'eks', '2026-03-24 10:00:00', '2026-03-24 10:00:00'),
                    ('c-aws-u2', 'user-2', 'user2-aws', 'aws', '2026-03-24 10:00:00', '2026-03-24 10:00:00')
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
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, expected_scans, created_at
                )
                VALUES
                    ('job-u1-a', 'user-1', 'c-eks-u1', 'g-u1-a', 'completed', '[]', '2026-03-24 10:00:00'),
                    ('job-u1-b', 'user-1', 'c-self-u1', 'g-u1-b', 'completed', '[]', '2026-03-24 10:00:00'),
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
async def test_me_overview_returns_counts_only_for_authenticated_user(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-1"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_clusters": 3,
        "eks_clusters": 1,
        "self_managed_clusters": 1,
        "aws_clusters": 1,
        "total_analysis_jobs": 2,
        "total_scan_records": 3,
        "total_attack_paths": 3,
        "total_remediation_recommendations": 3,
    }


@pytest.mark.asyncio
async def test_me_overview_excludes_another_users_data(overview_client):
    await _seed_overview_data(overview_client["sessionmaker"])

    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-2"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_clusters": 2,
        "eks_clusters": 1,
        "self_managed_clusters": 0,
        "aws_clusters": 1,
        "total_analysis_jobs": 1,
        "total_scan_records": 2,
        "total_attack_paths": 1,
        "total_remediation_recommendations": 1,
    }


@pytest.mark.asyncio
async def test_me_overview_returns_zeros_for_user_with_no_data(overview_client):
    response = overview_client["client"].get(
        "/api/v1/me/overview",
        headers=_auth_headers(overview_client["client"], "user-3"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_clusters": 0,
        "eks_clusters": 0,
        "self_managed_clusters": 0,
        "aws_clusters": 0,
        "total_analysis_jobs": 0,
        "total_scan_records": 0,
        "total_attack_paths": 0,
        "total_remediation_recommendations": 0,
    }
