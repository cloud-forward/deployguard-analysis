import pytest
from dataclasses import dataclass
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.di import get_analysis_service, get_auth_service
from app.application.services.analysis_service import AnalysisService
from app.application.services.auth_service import AuthService
from app.gateway.db.base import Base
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
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


@pytest.fixture
async def analysis_result_client(tmp_path):
    db_path = tmp_path / "analysis_result_api.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_analysis_service():
        async with sessionmaker() as session:
            yield AnalysisService(
                jobs_repo=SqlAlchemyAnalysisJobRepository(session=session),
                scan_repo=SQLAlchemyScanRepository(session=session),
                db=session,
            )

    app.dependency_overrides[get_analysis_service] = override_get_analysis_service
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_auth_service] = lambda: auth_service

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


@pytest.mark.asyncio
async def test_get_analysis_result_returns_job_scoped_persisted_static_result(analysis_result_client):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    graph_id = "11111111-1111-1111-1111-111111111111"
    job_id = "22222222-2222-2222-2222-222222222222"

    async with analysis_result_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, :name, 'eks', '2026-03-22 10:00:00', '2026-03-22 10:00:00')
                """
            ),
            {"id": cluster_id, "name": "result-cluster"},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status,
                    node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES (
                    :id, :cluster_id, 'k8s-1', 'aws-1', 'img-1', 'completed',
                    7, 8, 2, 1, '2026-03-22 10:05:00', '2026-03-22 10:00:00'
                )
                """
            ),
            {"id": graph_id, "cluster_id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, current_step,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans,
                    created_at, started_at, completed_at
                )
                VALUES (
                    :id, :user_id, :cluster_id, :graph_id, 'completed', NULL,
                    'k8s-1', 'aws-1', 'img-1', '["k8s","aws","image"]',
                    '2026-03-22 10:00:00', '2026-03-22 10:01:00', '2026-03-22 10:06:00'
                )
                """
            ),
            {"id": job_id, "user_id": "user-1", "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES
                    ('p-low', :graph_id, 'path-low', 'low', 0.2, 0.2, 2, 'entry-low', 'target-low', '["entry-low","mid-low","target-low"]'),
                    ('p-high-b', :graph_id, 'path-high-b', 'high', 0.8, 0.8, 2, 'entry-b', 'target-b', '["entry-b","mid-b","target-b"]'),
                    ('p-high-a', :graph_id, 'path-high-a', 'high', 0.8, 0.8, 1, 'entry-a', 'target-a', '["entry-a","target-a"]'),
                    ('p-critical', :graph_id, 'path-critical', 'critical', 0.9, 0.9, 3, 'entry-c', 'target-c', '["entry-c","mid-c1","mid-c2","target-c"]'),
                    ('p-medium', :graph_id, 'path-medium', 'medium', 0.5, 0.5, 1, 'entry-m', 'target-m', '["entry-m","target-m"]'),
                    ('p-none', :graph_id, 'path-none', 'none', 0.0, 0.0, 1, 'entry-n', 'target-n', '["entry-n","target-n"]')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_path_edges (id, path_id, sequence, source_node_id, target_node_id, edge_type)
                VALUES
                    ('ape-critical-0', 'p-critical', 0, 'entry-c', 'mid-c1', 'ingress_exposes_service'),
                    ('ape-critical-1', 'p-critical', 1, 'mid-c1', 'mid-c2', 'lateral_move'),
                    ('ape-critical-2', 'p-critical', 2, 'mid-c2', 'target-c', 'iam_role_access_resource'),
                    ('ape-high-a-0', 'p-high-a', 0, 'entry-a', 'target-a', 'secret_contains_credentials')
                """
            )
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_edges (id, graph_id, source_node_id, target_node_id, edge_type, metadata)
                VALUES
                    ('ge-critical-0', :graph_id, 'entry-c', 'mid-c1', 'ingress_exposes_service', '{"channel":"ingress"}'),
                    ('ge-critical-1', :graph_id, 'mid-c1', 'mid-c2', 'lateral_move', '{"channel":"east-west"}'),
                    ('ge-critical-2', :graph_id, 'mid-c2', 'target-c', 'iam_role_access_resource', '{"channel":"iam"}'),
                    ('ge-high-a-0', :graph_id, 'entry-a', 'target-a', 'secret_contains_credentials', '{"channel":"secret"}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    id, graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata,
                    llm_explanation, llm_provider, llm_model, llm_status, llm_generated_at, llm_error_message
                )
                VALUES
                    ('r3', :graph_id, 'rec-z', 2, 'a', 'b', 'type-z', 'fix-z', 'desc-z', '[]', '[]', 3.0, 0.1, 0.1, 0.9, '{}', NULL, NULL, NULL, NULL, NULL, NULL),
                    ('r2', :graph_id, 'rec-b', 1, 'a', 'b', 'type-b', 'fix-b', 'desc-b', '[]', '[]', 2.0, 0.2, 0.2, 0.8, '{}', NULL, NULL, NULL, NULL, NULL, NULL),
                    ('r1', :graph_id, 'rec-a', 1, 'a', 'b', 'type-a', 'fix-a', 'desc-a', '[]', '[]', 1.0, 0.3, 0.3, 1.0, '{}', 'Use IAM scoping.', 'openai', 'gpt-5.4', 'generated', '2026-03-22 10:07:00', NULL),
                    ('r0', :graph_id, 'rec-0', 0, 'a', 'b', 'type-0', 'fix-0', 'desc-0', '[]', '[]', 1.5, 0.4, 0.4, 0.7, '{}', NULL, 'openai', 'gpt-5.4-mini', 'failed', NULL, 'timeout'),
                    ('r4', :graph_id, 'rec-4', 4, 'a', 'b', 'type-4', 'fix-4', 'desc-4', '[]', '[]', 4.0, 0.05, 0.05, 1.0, '{}', NULL, NULL, NULL, NULL, NULL, NULL),
                    ('r5', :graph_id, 'rec-5', 5, 'a', 'b', 'type-5', 'fix-5', 'desc-5', '[]', '[]', 5.0, 0.01, 0.01, 1.0, '{}', NULL, NULL, NULL, NULL, NULL, NULL)
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["job"]["job_id"] == job_id
    assert body["job"]["cluster_id"] == cluster_id
    assert body["summary"] == {
        "graph_id": graph_id,
        "generated_at": "2026-03-22T10:05:00",
        "graph_status": "completed",
        "node_count": 7,
        "edge_count": 8,
        "entry_point_count": 2,
        "crown_jewel_count": 1,
        "attack_path_count": 6,
        "remediation_recommendation_count": 6,
    }
    assert [item["path_id"] for item in body["attack_paths_preview"]] == [
        "path-critical",
        "path-high-a",
        "path-high-b",
        "path-medium",
        "path-low",
    ]
    assert [item["path_id"] for item in body["attack_paths"][:2]] == [
        "path-critical",
        "path-high-a",
    ]
    assert body["attack_paths"][0]["edge_ids"] == ["ge-critical-0", "ge-critical-1", "ge-critical-2"]
    assert body["attack_paths"][0]["edges"] == [
        {
            "edge_id": "ape-critical-0",
            "edge_index": 0,
            "source_node_id": "entry-c",
            "target_node_id": "mid-c1",
            "edge_type": "ingress_exposes_service",
            "metadata": {},
        },
        {
            "edge_id": "ape-critical-1",
            "edge_index": 1,
            "source_node_id": "mid-c1",
            "target_node_id": "mid-c2",
            "edge_type": "lateral_move",
            "metadata": {},
        },
        {
            "edge_id": "ape-critical-2",
            "edge_index": 2,
            "source_node_id": "mid-c2",
            "target_node_id": "target-c",
            "edge_type": "iam_role_access_resource",
            "metadata": {},
        },
    ]
    assert [item["recommendation_id"] for item in body["remediation_preview"]] == [
        "rec-0",
        "rec-a",
        "rec-b",
        "rec-z",
        "rec-4",
    ]
    assert [item["recommendation_id"] for item in body["remediation_recommendations"][:4]] == [
        "rec-0",
        "rec-a",
        "rec-b",
        "rec-z",
    ]
    assert body["remediation_recommendations"][0]["llm_status"] == "failed"
    assert body["remediation_recommendations"][0]["llm_error_message"] == "timeout"
    assert body["remediation_recommendations"][1]["llm_explanation"] == "Use IAM scoping."
    assert body["remediation_recommendations"][1]["llm_provider"] == "openai"
    assert body["remediation_recommendations"][1]["llm_model"] == "gpt-5.4"
    assert body["remediation_recommendations"][1]["llm_status"] == "generated"
    assert body["remediation_recommendations"][1]["llm_generated_at"] == "2026-03-22T10:07:00"
    assert body["links"] == {
        "analysis_job": f"/api/v1/analysis/jobs/{job_id}",
        "attack_graph": f"/api/v1/clusters/{cluster_id}/attack-graph",
        "attack_paths": f"/api/v1/clusters/{cluster_id}/attack-paths",
        "remediation_recommendations": f"/api/v1/clusters/{cluster_id}/remediation-recommendations",
        "link_scope": "cluster_latest_view",
    }
    assert body["stats"] == {
        "facts": {"total": 0},
        "graph": {
            "nodes": 7,
            "edges": 8,
            "entry_points": 2,
            "crown_jewels": 1,
        },
        "paths": {
            "total": 6,
            "returned": 6,
        },
    }


@pytest.mark.asyncio
async def test_get_analysis_result_returns_404_for_unknown_job(analysis_result_client):
    response = analysis_result_client["client"].get(
        "/api/v1/analysis/33333333-3333-3333-3333-333333333333/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis job not found: 33333333-3333-3333-3333-333333333333"


@pytest.mark.asyncio
async def test_get_analysis_result_returns_empty_sections_when_job_has_no_graph(analysis_result_client):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    job_id = "44444444-4444-4444-4444-444444444444"

    async with analysis_result_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, :name, 'eks', '2026-03-22 10:00:00', '2026-03-22 10:00:00')
                """
            ),
            {"id": cluster_id, "name": "empty-result-cluster"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, current_step,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans, created_at
                )
                VALUES (
                    :id, :user_id, :cluster_id, NULL, 'running', 'graph_building',
                    'k8s-1', NULL, 'img-1', '["k8s","image"]', '2026-03-22 10:00:00'
                )
                """
            ),
            {"id": job_id, "user_id": "user-1", "cluster_id": cluster_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["job"]["job_id"] == job_id
    assert body["summary"] == {
        "graph_id": None,
        "generated_at": None,
        "graph_status": None,
        "node_count": 0,
        "edge_count": 0,
        "entry_point_count": 0,
        "crown_jewel_count": 0,
        "attack_path_count": 0,
        "remediation_recommendation_count": 0,
    }
    assert body["attack_paths_preview"] == []
    assert body["remediation_preview"] == []
    assert body["attack_paths"] == []
    assert body["remediation_recommendations"] == []
    assert body["links"]["analysis_job"] == f"/api/v1/analysis/jobs/{job_id}"
    assert body["stats"] is None


@pytest.mark.asyncio
async def test_get_analysis_result_returns_persisted_state_for_non_completed_job_with_graph(analysis_result_client):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    graph_id = "55555555-5555-5555-5555-555555555555"
    job_id = "66666666-6666-6666-6666-666666666666"

    async with analysis_result_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, :name, 'eks', '2026-03-22 10:00:00', '2026-03-22 10:00:00')
                """
            ),
            {"id": cluster_id, "name": "running-result-cluster"},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status,
                    node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES (
                    :id, :cluster_id, 'k8s-2', NULL, 'img-2', 'pending',
                    3, 2, 1, 1, NULL, '2026-03-22 11:00:00'
                )
                """
            ),
            {"id": graph_id, "cluster_id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, current_step,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans, created_at, started_at
                )
                VALUES (
                    :id, :user_id, :cluster_id, :graph_id, 'running', 'optimization',
                    'k8s-2', NULL, 'img-2', '["k8s","image"]', '2026-03-22 11:00:00', '2026-03-22 11:01:00'
                )
                """
            ),
            {"id": job_id, "user_id": "user-1", "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES (
                    'running-path-row', :graph_id, 'running-path', 'medium', 0.5, 0.5, 1,
                    'pod:prod:api', 'rds:prod-db', '["pod:prod:api","rds:prod-db"]'
                )
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    id, graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata
                )
                VALUES (
                    'running-rec-row', :graph_id, 'running-rec', 0, 'pod:prod:api', 'rds:prod-db', 'secret_contains_credentials',
                    'rotate_credentials', 'Rotate exposed credentials.', '["running-path"]', '[0]', 1.7, 0.5,
                    0.5, 0.5, '{}'
                )
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["job"]["job_id"] == job_id
    assert body["job"]["status"] == "running"
    assert body["job"]["current_step"] == "optimization"
    assert body["summary"] == {
        "graph_id": graph_id,
        "generated_at": None,
        "graph_status": "pending",
        "node_count": 3,
        "edge_count": 2,
        "entry_point_count": 1,
        "crown_jewel_count": 1,
        "attack_path_count": 1,
        "remediation_recommendation_count": 1,
    }
    assert [item["path_id"] for item in body["attack_paths_preview"]] == ["running-path"]
    assert [item["recommendation_id"] for item in body["remediation_preview"]] == ["running-rec"]
    assert [item["path_id"] for item in body["attack_paths"]] == ["running-path"]
    assert [item["recommendation_id"] for item in body["remediation_recommendations"]] == ["running-rec"]
    assert body["stats"] == {
        "facts": {"total": 0},
        "graph": {
            "nodes": 3,
            "edges": 2,
            "entry_points": 1,
            "crown_jewels": 1,
        },
        "paths": {
            "total": 1,
            "returned": 1,
        },
    }


@pytest.mark.asyncio
async def test_get_analysis_result_isolated_by_requested_job_graph_when_jobs_share_scan_tuple(analysis_result_client):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    first_graph_id = "77777777-7777-7777-7777-777777777777"
    second_graph_id = "88888888-8888-8888-8888-888888888888"
    first_job_id = "99999999-9999-9999-9999-999999999999"
    second_job_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    async with analysis_result_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, :name, 'eks', '2026-03-22 10:00:00', '2026-03-22 10:00:00')
                """
            ),
            {"id": cluster_id, "name": "duplicated-scan-tuple-cluster"},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status, created_at)
                VALUES
                    (:first_graph_id, :cluster_id, 'k8s-1', 'aws-1', 'img-1', 'completed', '2026-03-22 10:00:00'),
                    (:second_graph_id, :cluster_id, 'k8s-1', 'aws-1', 'img-1', 'completed', '2026-03-22 10:10:00')
                """
            ),
            {"first_graph_id": first_graph_id, "second_graph_id": second_graph_id, "cluster_id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans, created_at
                )
                VALUES
                    (:first_job_id, 'user-1', :cluster_id, :first_graph_id, 'completed', 'k8s-1', 'aws-1', 'img-1', '["k8s","aws","image"]', '2026-03-22 10:00:00'),
                    (:second_job_id, 'user-1', :cluster_id, :second_graph_id, 'completed', 'k8s-1', 'aws-1', 'img-1', '["k8s","aws","image"]', '2026-03-22 10:10:00')
                """
            ),
            {
                "first_job_id": first_job_id,
                "second_job_id": second_job_id,
                "cluster_id": cluster_id,
                "first_graph_id": first_graph_id,
                "second_graph_id": second_graph_id,
            },
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (id, graph_id, path_id, risk_level, risk_score, raw_final_risk, hop_count, entry_node_id, target_node_id, node_ids)
                VALUES
                    ('first-path-row', :first_graph_id, 'first-path', 'high', 0.8, 0.8, 1, 'entry-1', 'target-1', '["entry-1","target-1"]'),
                    ('second-path-row', :second_graph_id, 'second-path', 'low', 0.2, 0.2, 1, 'entry-2', 'target-2', '["entry-2","target-2"]')
                """
            ),
            {"first_graph_id": first_graph_id, "second_graph_id": second_graph_id},
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
                    ('first-rec-row', :first_graph_id, 'first-rec', 0, 'entry-1', 'target-1', 'type-1', 'fix-1', 'desc-1', '["first-path"]', '[0]', 1.0, 0.8, 0.8, 0.8, '{}'),
                    ('second-rec-row', :second_graph_id, 'second-rec', 0, 'entry-2', 'target-2', 'type-2', 'fix-2', 'desc-2', '["second-path"]', '[0]', 1.0, 0.2, 0.2, 0.2, '{}')
                """
            ),
            {"first_graph_id": first_graph_id, "second_graph_id": second_graph_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{first_job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["summary"]["graph_id"] == first_graph_id
    assert [item["path_id"] for item in body["attack_paths"]] == ["first-path"]
    assert [item["recommendation_id"] for item in body["remediation_recommendations"]] == ["first-rec"]
    assert body["stats"]["paths"]["total"] == 1
    assert body["stats"]["paths"]["returned"] == 1
    assert body["stats"]["graph"]["nodes"] == 0


@pytest.mark.asyncio
async def test_get_analysis_result_returns_non_null_risk_from_legacy_schema(analysis_result_client):
    """Verify that risk_score and raw_final_risk are non-null when the attack_paths
    table has only legacy columns (base_risk, final_risk) instead of the new columns."""
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    graph_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    job_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"

    async with analysis_result_client["sessionmaker"]() as session:
        # Migrate attack_paths to legacy schema
        await session.execute(text("ALTER TABLE attack_paths DROP COLUMN risk_score"))
        await session.execute(text("ALTER TABLE attack_paths DROP COLUMN raw_final_risk"))
        await session.execute(text("ALTER TABLE attack_paths ADD COLUMN base_risk REAL"))
        await session.execute(text("ALTER TABLE attack_paths ADD COLUMN final_risk REAL"))
        await session.execute(text("ALTER TABLE attack_paths ADD COLUMN name TEXT"))

        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, 'legacy-cluster', 'eks', '2026-03-22 10:00:00', '2026-03-22 10:00:00')
                """
            ),
            {"id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status,
                    node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES (
                    :id, :cluster_id, 'k8s-1', 'aws-1', 'img-1', 'completed',
                    3, 2, 1, 1, '2026-03-22 10:05:00', '2026-03-22 10:00:00'
                )
                """
            ),
            {"id": graph_id, "cluster_id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, current_step,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans,
                    created_at, started_at, completed_at
                )
                VALUES (
                    :id, :user_id, :cluster_id, :graph_id, 'completed', NULL,
                    'k8s-1', 'aws-1', 'img-1', '["k8s","aws","image"]',
                    '2026-03-22 10:00:00', '2026-03-22 10:01:00', '2026-03-22 10:06:00'
                )
                """
            ),
            {"id": job_id, "user_id": "user-1", "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, base_risk, final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids, name
                )
                VALUES
                    ('leg-p1', :graph_id, 'legacy-path-1', 'critical', 0.65, 0.85,
                     2, 'entry-x', 'target-x', '["entry-x","mid-x","target-x"]', 'Legacy Path One')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    preview_items = body["attack_paths_preview"]
    assert len(preview_items) == 1
    assert preview_items[0]["path_id"] == "legacy-path-1"
    assert preview_items[0]["risk_score"] is not None
    assert abs(preview_items[0]["risk_score"] - 0.65) < 1e-6
    assert preview_items[0]["raw_final_risk"] is not None
    assert abs(preview_items[0]["raw_final_risk"] - 0.85) < 1e-6

    detail_items = body["attack_paths"]
    assert len(detail_items) == 1
    assert detail_items[0]["path_id"] == "legacy-path-1"
    assert detail_items[0]["risk_score"] is not None
    assert abs(detail_items[0]["risk_score"] - 0.65) < 1e-6
    assert detail_items[0]["raw_final_risk"] is not None
    assert abs(detail_items[0]["raw_final_risk"] - 0.85) < 1e-6


@pytest.mark.asyncio
async def test_get_analysis_result_returns_canonical_risk_columns_when_present(analysis_result_client):
    """Verify that risk_score and raw_final_risk are read from canonical columns
    (not legacy base_risk/final_risk) when the canonical columns are present and populated."""
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    graph_id = "dddddddd-dddd-dddd-dddd-dddddddddddd"
    job_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

    async with analysis_result_client["sessionmaker"]() as session:
        await session.execute(
            text(
                """
                INSERT INTO clusters (id, name, cluster_type, created_at, updated_at)
                VALUES (:id, 'canonical-cluster', 'eks', '2026-03-31 10:00:00', '2026-03-31 10:00:00')
                """
            ),
            {"id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_snapshots (
                    id, cluster_id, k8s_scan_id, aws_scan_id, image_scan_id, status,
                    node_count, edge_count, entry_point_count, crown_jewel_count, completed_at, created_at
                )
                VALUES (
                    :id, :cluster_id, 'k8s-1', 'aws-1', 'img-1', 'completed',
                    2, 1, 1, 1, '2026-03-31 10:05:00', '2026-03-31 10:00:00'
                )
                """
            ),
            {"id": graph_id, "cluster_id": cluster_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (
                    id, user_id, cluster_id, graph_id, status, current_step,
                    k8s_scan_id, aws_scan_id, image_scan_id, expected_scans,
                    created_at, started_at, completed_at
                )
                VALUES (
                    :id, :user_id, :cluster_id, :graph_id, 'completed', NULL,
                    'k8s-1', 'aws-1', 'img-1', '["k8s","aws","image"]',
                    '2026-03-31 10:00:00', '2026-03-31 10:01:00', '2026-03-31 10:06:00'
                )
                """
            ),
            {"id": job_id, "user_id": "user-1", "cluster_id": cluster_id, "graph_id": graph_id},
        )
        # Insert with canonical columns risk_score and raw_final_risk populated.
        # These values must appear in the response unchanged.
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES
                    ('can-p1', :graph_id, 'canonical-path-1', 'critical', 0.73, 0.91,
                     2, 'entry-can', 'target-can', '["entry-can","mid-can","target-can"]')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = analysis_result_client["client"].get(
        f"/api/v1/analysis/{job_id}/result",
        headers=_auth_headers(analysis_result_client["client"], "user-1"),
    )
    assert response.status_code == 200
    body = response.json()

    # attack_paths_preview (test C)
    preview_items = body["attack_paths_preview"]
    assert len(preview_items) == 1
    assert preview_items[0]["path_id"] == "canonical-path-1"
    assert preview_items[0]["risk_score"] is not None
    assert abs(preview_items[0]["risk_score"] - 0.73) < 1e-6
    assert preview_items[0]["raw_final_risk"] is not None
    assert abs(preview_items[0]["raw_final_risk"] - 0.91) < 1e-6

    # attack_paths detail section (test A)
    detail_items = body["attack_paths"]
    assert len(detail_items) == 1
    assert detail_items[0]["path_id"] == "canonical-path-1"
    assert detail_items[0]["risk_score"] is not None
    assert abs(detail_items[0]["risk_score"] - 0.73) < 1e-6
    assert detail_items[0]["raw_final_risk"] is not None
    assert abs(detail_items[0]["raw_final_risk"] - 0.91) < 1e-6
