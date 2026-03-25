import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.di import get_attack_graph_service, get_cluster_service, get_recommendation_explanation_service
from app.application.services.attack_graph_service import AttackGraphService
from app.application.services.cluster_service import ClusterService
from app.application.services.recommendation_explanation_service import RecommendationExplanationService
from app.gateway.db.base import Base
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.main import app

USER_HEADERS = {"X-User-Id": "user-1"}


def test_create_cluster(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "test-cluster",
            "cluster_type": "eks",
            "description": "A test cluster"
        },
        headers=USER_HEADERS,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-cluster"
    assert data["cluster_type"] == "eks"
    assert "id" in data
    assert "api_token" in data
    assert data["api_token"]
    assert data["onboarding"]["installation_method"] == "helm"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_values"]["imagePullSecret"] == "deployguard-registry"


def test_create_cluster_with_aws_type(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "aws-test-cluster",
            "cluster_type": "aws",
        },
        headers=USER_HEADERS,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["cluster_type"] == "aws"
    assert data["onboarding"]["installation_method"] == "docker-compose"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_environment_variables"] == [
        "DEPLOYGUARD_CLUSTER_ID",
        "DEPLOYGUARD_API_TOKEN",
        "AWS_REGION",
        "AWS_ROLE_ARN",
    ]
    assert any("IAM role" in item for item in data["onboarding"]["guidance"])


def test_create_cluster_with_self_managed_type(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "self-managed-test-cluster",
            "cluster_type": "self-managed",
        },
        headers=USER_HEADERS,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["cluster_type"] == "self-managed"
    assert data["onboarding"]["installation_method"] == "helm"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_values"]["imagePullSecret"] == "deployguard-registry"


def test_create_cluster_invalid_type(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "invalid-cluster",
            "cluster_type": "invalid"
        },
        headers=USER_HEADERS,
    )
    assert response.status_code == 422


def test_list_clusters(client):
    client.post("/api/v1/clusters", json={"name": "c1", "cluster_type": "eks"}, headers=USER_HEADERS)
    client.post("/api/v1/clusters", json={"name": "c2", "cluster_type": "self-managed"}, headers=USER_HEADERS)
    
    response = client.get("/api/v1/clusters", headers=USER_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2
    assert all("api_token" not in c for c in data)


def test_list_clusters_returns_only_clusters_for_requesting_user(client):
    client.post("/api/v1/clusters", json={"name": "user-1-cluster", "cluster_type": "eks"}, headers={"X-User-Id": "user-1"})
    client.post("/api/v1/clusters", json={"name": "user-2-cluster", "cluster_type": "eks"}, headers={"X-User-Id": "user-2"})

    response = client.get("/api/v1/clusters", headers={"X-User-Id": "user-1"})

    assert response.status_code == 200
    names = [cluster["name"] for cluster in response.json()]
    assert "user-1-cluster" in names
    assert "user-2-cluster" not in names

def test_get_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "get-me", "cluster_type": "eks"}, headers=USER_HEADERS)
    cluster_id = create_resp.json()["id"]
    
    response = client.get(f"/api/v1/clusters/{cluster_id}", headers=USER_HEADERS)
    assert response.status_code == 200
    assert response.json()["name"] == "get-me"
    assert "api_token" not in response.json()


def test_get_cluster_returns_not_found_for_other_users_cluster(client):
    create_resp = client.post(
        "/api/v1/clusters",
        json={"name": "other-users-detail", "cluster_type": "eks"},
        headers={"X-User-Id": "user-2"},
    )

    response = client.get(
        f"/api/v1/clusters/{create_resp.json()['id']}",
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()

def test_update_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "update-me", "cluster_type": "eks"}, headers=USER_HEADERS)
    cluster_id = create_resp.json()["id"]
    
    response = client.patch(
        f"/api/v1/clusters/{cluster_id}",
        json={"description": "updated description", "cluster_type": "self-managed"},
        headers=USER_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["description"] == "updated description"
    assert data["cluster_type"] == "self-managed"


def test_update_cluster_returns_not_found_for_other_users_cluster(client):
    create_resp = client.post(
        "/api/v1/clusters",
        json={"name": "other-users-update", "cluster_type": "eks"},
        headers={"X-User-Id": "user-2"},
    )
    cluster_id = create_resp.json()["id"]

    response = client.patch(
        f"/api/v1/clusters/{cluster_id}",
        json={"description": "should-not-update"},
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()

def test_delete_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "delete-me", "cluster_type": "eks"}, headers=USER_HEADERS)
    cluster_id = create_resp.json()["id"]
    
    del_resp = client.delete(f"/api/v1/clusters/{cluster_id}")
    assert del_resp.status_code == 204
    
    get_resp = client.get(f"/api/v1/clusters/{cluster_id}", headers=USER_HEADERS)
    assert get_resp.status_code == 404


def test_create_cluster_token_is_persisted_for_auth_lookup():
    app.dependency_overrides.clear()
    name = f"persist-{uuid4().hex[:8]}"
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": name, "cluster_type": "eks"},
            headers=USER_HEADERS,
        )
        assert create_resp.status_code == 201
        token = create_resp.json()["api_token"]

        pending_resp = client.get(
            "/api/v1/scans/pending",
            params={"scanner_type": "k8s"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert pending_resp.status_code == 204


@pytest.fixture
async def attack_graph_client(tmp_path):
    db_path = tmp_path / "attack_graph_api.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("DROP TABLE IF EXISTS remediation_recommendations"))
        await conn.execute(text("DROP TABLE IF EXISTS attack_path_edges"))
        await conn.execute(text("DROP TABLE IF EXISTS attack_paths"))
        await conn.execute(text("DROP TABLE IF EXISTS graph_edges"))
        await conn.execute(text("DROP TABLE IF EXISTS graph_nodes"))
        await conn.execute(text("""
            CREATE TABLE graph_nodes (
                graph_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                label TEXT,
                risk_level TEXT,
                has_runtime_evidence BOOLEAN,
                is_entry_point BOOLEAN,
                is_crown_jewel BOOLEAN,
                metadata TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE graph_edges (
                id TEXT NOT NULL,
                graph_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                edge_type TEXT,
                metadata TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE attack_paths (
                id TEXT NOT NULL,
                graph_id TEXT NOT NULL,
                path_id TEXT NOT NULL,
                risk_level TEXT,
                risk_score REAL,
                raw_final_risk REAL,
                hop_count INTEGER,
                entry_node_id TEXT,
                target_node_id TEXT,
                node_ids TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE attack_path_edges (
                id TEXT NOT NULL,
                path_id TEXT NOT NULL,
                source_node_id TEXT,
                target_node_id TEXT,
                edge_type TEXT,
                sequence INTEGER,
                metadata TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE remediation_recommendations (
                graph_id TEXT NOT NULL,
                recommendation_id TEXT NOT NULL,
                recommendation_rank INTEGER NOT NULL,
                edge_source TEXT,
                edge_target TEXT,
                edge_type TEXT,
                fix_type TEXT,
                fix_description TEXT,
                blocked_path_ids TEXT,
                blocked_path_indices TEXT,
                fix_cost REAL,
                edge_score REAL,
                covered_risk REAL,
                cumulative_risk_reduction REAL,
                metadata TEXT
            )
        """))

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_cluster_service():
        async with sessionmaker() as session:
            yield ClusterService(cluster_repository=SQLAlchemyClusterRepository(session))

    async def override_get_attack_graph_service():
        async with sessionmaker() as session:
            yield AttackGraphService(cluster_repository=SQLAlchemyClusterRepository(session), db=session)

    app.dependency_overrides[get_cluster_service] = override_get_cluster_service
    app.dependency_overrides[get_attack_graph_service] = override_get_attack_graph_service

    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": "graph-cluster", "cluster_type": "eks"},
            headers=USER_HEADERS,
        )
        assert create_resp.status_code == 201
        yield {"client": client, "cluster_id": create_resp.json()["id"], "sessionmaker": sessionmaker}

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_get_attack_graph_returns_mvp_contract(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-1"
    analysis_run_id = "analysis-1"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 10:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 10:00:00', '2026-03-22 10:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    graph_id, node_id, node_type, label, risk_level,
                    has_runtime_evidence, is_entry_point, is_crown_jewel, metadata
                )
                VALUES
                    (:graph_id, 'ingress:prod:web', 'ingress', 'Public Web Ingress', 'critical', 1, 1, 0, '{"namespace":"prod"}'),
                    (:graph_id, 'pod:prod:api', 'pod', 'API Pod', NULL, NULL, NULL, NULL, NULL),
                    (:graph_id, 's3:prod-secrets', 's3_bucket', 'Secrets Bucket', 'high', 0, 0, 1, '{"account_id":"123456789012"}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_edges (id, graph_id, source_node_id, target_node_id, edge_type, metadata)
                VALUES
                    ('edge-1', :graph_id, 'ingress:prod:web', 'pod:prod:api', 'allows', '{"protocol":"http"}'),
                    ('edge-2', :graph_id, 'pod:prod:api', 's3:prod-secrets', 'accesses', NULL)
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (id, graph_id, path_id, risk_level, node_ids)
                VALUES ('path-row-1', :graph_id, 'path-1', 'critical',
                        '["ingress:prod:web","pod:prod:api","s3:prod-secrets"]')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_path_edges (id, path_id, source_node_id, target_node_id, edge_type, sequence, metadata)
                VALUES
                    ('path-1-step-0', 'path-row-1', 'ingress:prod:web', 'pod:prod:api', 'allows', 0, '{"protocol":"http"}'),
                    ('path-1-step-1', 'path-row-1', 'pod:prod:api', 's3:prod-secrets', 'accesses', 1, NULL)
                """
            )
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/attack-graph")
    assert response.status_code == 200

    body = response.json()
    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T10:05:00"
    assert body["paths"] == [{
        "id": "path-1",
        "title": "Public Web Ingress -> Secrets Bucket",
        "summary": "Public Web Ingress to Secrets Bucket in 2 hops",
        "severity": "critical",
        "evidence_count": 1,
        "node_ids": ["ingress:prod:web", "pod:prod:api", "s3:prod-secrets"],
        "edge_ids": ["edge-1", "edge-2"],
    }]

    pod_node = next(node for node in body["nodes"] if node["id"] == "pod:prod:api")
    assert pod_node == {
        "id": "pod:prod:api",
        "type": "pod",
        "label": "API Pod",
        "severity": "none",
        "has_runtime_evidence": False,
        "is_entry_point": False,
        "is_crown_jewel": False,
        "metadata": {"kind_display": "Pod"},
    }

    assert body["edges"] == [
        {
            "id": "edge-1",
            "source": "ingress:prod:web",
            "target": "pod:prod:api",
            "type": "allows",
            "metadata": {
                "protocol": "http",
                "reason": "A connectivity or permission relationship exists between these nodes.",
            },
        },
        {
            "id": "edge-2",
            "source": "pod:prod:api",
            "target": "s3:prod-secrets",
            "type": "accesses",
            "metadata": {"reason": "An access relationship exists between these nodes."},
        },
    ]


@pytest.mark.asyncio
async def test_get_attack_paths_returns_persisted_cluster_scoped_list(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-paths-1"
    analysis_run_id = "analysis-paths-1"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 12:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 12:00:00', '2026-03-22 12:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES
                    ('path-row-high', :graph_id, 'path-high', 'high', 0.8, 0.8, 2, 'ingress:prod:web', 's3:prod-secrets',
                     '["ingress:prod:web","pod:prod:api","s3:prod-secrets"]'),
                    ('path-row-medium', :graph_id, 'path-medium', 'medium', 0.5, 0.5, 1, 'pod:prod:api', 'rds:prod-db',
                     '["pod:prod:api","rds:prod-db"]')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/attack-paths")
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T12:05:00"
    assert [item["path_id"] for item in body["items"]] == ["path-high", "path-medium"]
    assert body["items"][0] == {
        "path_id": "path-high",
        "title": "ingress:prod:web -> s3:prod-secrets",
        "risk_level": "high",
        "risk_score": 0.8,
        "raw_final_risk": 0.8,
        "hop_count": 2,
        "entry_node_id": "ingress:prod:web",
        "target_node_id": "s3:prod-secrets",
        "node_ids": ["ingress:prod:web", "pod:prod:api", "s3:prod-secrets"],
    }


@pytest.mark.asyncio
async def test_get_attack_path_detail_returns_ordered_edge_sequence(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-paths-2"
    analysis_run_id = "analysis-paths-2"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 13:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 13:00:00', '2026-03-22 13:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (
                    id, graph_id, path_id, risk_level, risk_score, raw_final_risk,
                    hop_count, entry_node_id, target_node_id, node_ids
                )
                VALUES (
                    'path-row-detail', :graph_id, 'path-detail', 'critical', 0.95, 0.95, 2,
                    'ingress:prod:web', 's3:prod-secrets',
                    '["ingress:prod:web","pod:prod:api","s3:prod-secrets"]'
                )
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_edges (id, graph_id, source_node_id, target_node_id, edge_type, metadata)
                VALUES
                    ('edge-detail-1', :graph_id, 'ingress:prod:web', 'pod:prod:api', 'ingress_exposes_service', '{"protocol":"http"}'),
                    ('edge-detail-2', :graph_id, 'pod:prod:api', 's3:prod-secrets', 'iam_role_access_resource', '{"service":"s3"}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_path_edges (
                    id, path_id, source_node_id, target_node_id, edge_type, sequence, metadata
                )
                VALUES
                    ('path-detail:edge:0', 'path-row-detail', 'ingress:prod:web', 'pod:prod:api', 'ingress_exposes_service', 0, '{"protocol":"http"}'),
                    ('path-detail:edge:1', 'path-row-detail', 'pod:prod:api', 's3:prod-secrets', 'iam_role_access_resource', 1, '{"service":"s3"}')
                """
            ),
            {},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/attack-paths/path-detail")
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T13:05:00"
    assert body["path"]["path_id"] == "path-detail"
    assert body["path"]["risk_level"] == "critical"
    assert body["path"]["raw_final_risk"] == 0.95
    assert body["path"]["edge_ids"] == ["edge-detail-1", "edge-detail-2"]
    assert body["path"]["edges"] == [
        {
            "edge_id": "path-detail:edge:0",
            "edge_index": 0,
            "source_node_id": "ingress:prod:web",
            "target_node_id": "pod:prod:api",
            "edge_type": "ingress_exposes_service",
            "metadata": {"protocol": "http"},
        },
        {
            "edge_id": "path-detail:edge:1",
            "edge_index": 1,
            "source_node_id": "pod:prod:api",
            "target_node_id": "s3:prod-secrets",
            "edge_type": "iam_role_access_resource",
            "metadata": {"service": "s3"},
        },
    ]


@pytest.mark.asyncio
async def test_get_remediation_recommendations_returns_ranked_cluster_scoped_list(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-1"
    analysis_run_id = "analysis-recommendations-1"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 14:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 14:00:00', '2026-03-22 14:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata
                )
                VALUES
                    (:graph_id, 'restrict-ingress-1', 0, 'ingress:prod:web', 'service:prod:web', 'ingress_exposes_service',
                     'restrict_ingress', 'Restrict public ingress exposure.', '["path-a","path-b"]', '[0,1]', 1.0, 1.5,
                     1.5, 1.5, '{"edge_source_type":"ingress"}'),
                    (:graph_id, 'remove-privileged-2', 1, 'pod:prod:escape', 'node:worker-1', 'escapes_to',
                     'remove_privileged', 'Remove the privileged pod config.', '["path-c"]', '[2]', 2.2, 0.7,
                     0.7, 2.2, '{"edge_source_type":"pod"}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/remediation-recommendations")
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T14:05:00"
    assert [item["recommendation_id"] for item in body["items"]] == ["restrict-ingress-1", "remove-privileged-2"]
    assert body["items"][0] == {
        "recommendation_id": "restrict-ingress-1",
        "recommendation_rank": 0,
        "edge_source": "ingress:prod:web",
        "edge_target": "service:prod:web",
        "edge_type": "ingress_exposes_service",
        "fix_type": "restrict_ingress",
        "fix_description": "Restrict public ingress exposure.",
        "blocked_path_ids": ["path-a", "path-b"],
        "blocked_path_indices": [0, 1],
        "fix_cost": 1.0,
        "edge_score": 1.5,
        "covered_risk": 1.5,
        "cumulative_risk_reduction": 1.5,
        "metadata": {"edge_source_type": "ingress"},
    }


@pytest.mark.asyncio
async def test_get_remediation_recommendations_returns_empty_list_when_latest_graph_has_no_rows(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-empty"
    analysis_run_id = "analysis-recommendations-empty"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 14:30:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 14:30:00', '2026-03-22 14:35:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/remediation-recommendations")
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T14:35:00"
    assert body["items"] == []


@pytest.mark.asyncio
async def test_get_remediation_recommendations_returns_empty_list_when_table_is_missing(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-missing-table"
    analysis_run_id = "analysis-recommendations-missing-table"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(text("DROP TABLE IF EXISTS remediation_recommendations"))
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 14:40:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 14:40:00', '2026-03-22 14:45:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/remediation-recommendations")
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T14:45:00"
    assert body["items"] == []


@pytest.mark.asyncio
async def test_get_remediation_recommendations_orders_by_rank_then_cumulative_reduction_then_id(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-ordering"
    analysis_run_id = "analysis-recommendations-ordering"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 16:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 16:00:00', '2026-03-22 16:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata
                )
                VALUES
                    (:graph_id, 'z-rank-0', 0, 'a', 'b', 'ingress_exposes_service',
                     'restrict_ingress', 'rank 0 first', '["path-a"]', '[0]', 1.0, 0.5,
                     0.5, 0.4, '{}'),
                    (:graph_id, 'z-rank-1-lower-cumulative', 1, 'c', 'd', 'pod_mounts_secret',
                     'remove_secret_mount', 'rank 1 lower cumulative', '["path-b"]', '[1]', 1.0, 0.5,
                     0.5, 0.5, '{}'),
                    (:graph_id, 'a-rank-1-higher-cumulative', 1, 'e', 'f', 'pod_mounts_secret',
                     'remove_secret_mount', 'rank 1 higher cumulative', '["path-c"]', '[2]', 1.0, 0.5,
                     0.5, 0.9, '{}'),
                    (:graph_id, 'a-rank-1-same-cumulative', 1, 'g', 'h', 'pod_mounts_secret',
                     'remove_secret_mount', 'rank 1 same cumulative lower id', '["path-d"]', '[3]', 1.0, 0.5,
                     0.5, 0.5, '{}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/remediation-recommendations")
    assert response.status_code == 200
    body = response.json()

    assert [item["recommendation_id"] for item in body["items"]] == [
        "z-rank-0",
        "a-rank-1-higher-cumulative",
        "a-rank-1-same-cumulative",
        "z-rank-1-lower-cumulative",
    ]


@pytest.mark.asyncio
async def test_get_remediation_recommendation_detail_returns_persisted_row(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-2"
    analysis_run_id = "analysis-recommendations-2"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 15:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 15:00:00', '2026-03-22 15:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO remediation_recommendations (
                    graph_id, recommendation_id, recommendation_rank, edge_source, edge_target, edge_type,
                    fix_type, fix_description, blocked_path_ids, blocked_path_indices, fix_cost, edge_score,
                    covered_risk, cumulative_risk_reduction, metadata
                )
                VALUES (
                    :graph_id, 'rotate-credentials-1', 0, 'secret:prod:db-creds', 'rds:prod-db', 'secret_contains_credentials',
                    'rotate_credentials', 'Rotate exposed database credentials.', '["path-db"]', '[4]', 1.3, 0.9,
                    0.9, 0.9, '{"secret_type":"db"}'
                )
                """
            ),
            {"graph_id": graph_id},
        )
        await session.commit()

    response = attack_graph_client["client"].get(
        f"/api/v1/clusters/{cluster_id}/remediation-recommendations/rotate-credentials-1"
    )
    assert response.status_code == 200
    body = response.json()

    assert body["cluster_id"] == cluster_id
    assert body["analysis_run_id"] == analysis_run_id
    assert body["generated_at"] == "2026-03-22T15:05:00"
    assert body["recommendation"] == {
        "recommendation_id": "rotate-credentials-1",
        "recommendation_rank": 0,
        "edge_source": "secret:prod:db-creds",
        "edge_target": "rds:prod-db",
        "edge_type": "secret_contains_credentials",
        "fix_type": "rotate_credentials",
        "fix_description": "Rotate exposed database credentials.",
        "blocked_path_ids": ["path-db"],
        "blocked_path_indices": [4],
        "fix_cost": 1.3,
        "edge_score": 0.9,
        "covered_risk": 0.9,
        "cumulative_risk_reduction": 0.9,
        "metadata": {"secret_type": "db"},
    }


class _MissingConfigRepo:
    async def get_active(self, user_id: str):
        return None

    async def get_by_provider(self, user_id: str, provider: str):
        return None


class _RecordingProvider:
    provider_name = "openai"

    def __init__(self):
        self.calls = []

    async def generate_explanation(self, prompt):
        self.calls.append(prompt)
        raise AssertionError("provider should not be called")


@pytest.mark.asyncio
async def test_post_remediation_recommendation_explanation_returns_no_target_when_row_missing_under_existing_graph(
    attack_graph_client,
):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-recommendations-missing-target"
    analysis_run_id = "analysis-recommendations-missing-target"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 15:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 15:00:00', '2026-03-22 15:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.commit()

    provider = _RecordingProvider()

    async def override_get_recommendation_explanation_service():
        async with attack_graph_client["sessionmaker"]() as session:
            yield RecommendationExplanationService(
                attack_graph_service=AttackGraphService(
                    cluster_repository=SQLAlchemyClusterRepository(session),
                    db=session,
                ),
                provider_config_repository=_MissingConfigRepo(),
                providers={"openai": provider},
            )

    app.dependency_overrides[get_recommendation_explanation_service] = override_get_recommendation_explanation_service
    response = attack_graph_client["client"].post(
        f"/api/v1/clusters/{cluster_id}/remediation-recommendations/missing-rec/explanation",
        json={},
        headers={"X-User-Id": "user-1"},
    )
    app.dependency_overrides.pop(get_recommendation_explanation_service, None)

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == cluster_id
    assert body["recommendation_id"] == "missing-rec"
    assert body["explanation_status"] == "no_target"
    assert body["used_llm"] is False
    assert body["provider"] is None
    assert body["model"] is None
    assert body["fallback_reason"] == "recommendation_not_found"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_get_attack_graph_returns_empty_payload_when_no_analysis_exists(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/attack-graph")

    assert response.status_code == 200
    assert response.json() == {
        "cluster_id": cluster_id,
        "analysis_run_id": None,
        "generated_at": None,
        "nodes": [],
        "edges": [],
        "paths": [],
    }


@pytest.mark.asyncio
async def test_get_attack_graph_normalizes_enums_and_skips_invalid_references(attack_graph_client):
    cluster_id = attack_graph_client["cluster_id"]
    graph_id = "graph-2"
    analysis_run_id = "analysis-2"

    async with attack_graph_client["sessionmaker"]() as session:
        await session.execute(
            text("INSERT INTO graph_snapshots (id, cluster_id, created_at) VALUES (:id, :cluster_id, :created_at)"),
            {"id": graph_id, "cluster_id": cluster_id, "created_at": "2026-03-22 11:00:00"},
        )
        await session.execute(
            text(
                """
                INSERT INTO analysis_jobs (id, cluster_id, graph_id, status, created_at, completed_at)
                VALUES (:id, :cluster_id, :graph_id, 'completed', '2026-03-22 11:00:00', '2026-03-22 11:05:00')
                """
            ),
            {"id": analysis_run_id, "cluster_id": cluster_id, "graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    graph_id, node_id, node_type, label, risk_level,
                    has_runtime_evidence, is_entry_point, is_crown_jewel, metadata
                )
                VALUES
                    (:graph_id, 'sa:prod:api', 'sa', '', 'urgent', NULL, NULL, NULL, '{"namespace":"prod","serviceAccount":"api-sa"}'),
                    (:graph_id, 's3:archive', 'bucket', 'Archive Bucket', NULL, 0, 0, 0, '[]'),
                    (:graph_id, 'mystery:asset', 'totally_custom', NULL, NULL, 'yes', 'no', NULL, '{"kind":"mystery","image":"distroless:latest"}')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO graph_edges (id, graph_id, source_node_id, target_node_id, edge_type, metadata)
                VALUES
                    ('edge-keep-1', :graph_id, 'sa:prod:api', 's3:archive', 'service_account_assumes_iam_role', :edge_keep_1_metadata),
                    ('edge-keep-2', :graph_id, 's3:archive', 'mystery:asset', 'totally_custom', :edge_keep_2_metadata),
                    ('edge-drop', :graph_id, 'ghost:src', 's3:archive', 'allows', NULL)
                """
            ),
            {
                "graph_id": graph_id,
                "edge_keep_1_metadata": '{"has_runtime_evidence":true}',
                "edge_keep_2_metadata": '{"raw":1}',
            },
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (id, graph_id, path_id, risk_level, node_ids)
                    VALUES
                        ('path-row-keep', :graph_id, 'path-keep', 'urgent',
                            '["sa:prod:api","s3:archive","mystery:asset"]'),
                        ('path-row-drop-node', :graph_id, 'path-drop-missing-node', 'high',
                            '["sa:prod:api","ghost:node"]'),
                        ('path-row-drop-edge', :graph_id, 'path-drop-missing-edge', 'low',
                            '["sa:prod:api","mystery:asset"]')
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_path_edges (id, path_id, source_node_id, target_node_id, edge_type, sequence, metadata)
                VALUES
                        ('path-keep-step-0', 'path-row-keep', 'sa:prod:api', 's3:archive', 'service_account_assumes_iam_role', 0, NULL),
                        ('path-keep-step-1', 'path-row-keep', 's3:archive', 'mystery:asset', 'totally_custom', 1, NULL),
                        ('path-drop-node-step-0', 'path-row-drop-node', 'sa:prod:api', 'ghost:node', 'service_account_assumes_iam_role', 0, NULL),
                        ('path-drop-edge-step-0', 'path-row-drop-edge', 'sa:prod:api', 'ghost:edge', 'service_account_assumes_iam_role', 0, NULL)
                    """
                )
            )
        await session.commit()

    response = attack_graph_client["client"].get(f"/api/v1/clusters/{cluster_id}/attack-graph")
    assert response.status_code == 200

    body = response.json()
    assert body["analysis_run_id"] == analysis_run_id

    assert body["nodes"] == [
        {
            "id": "mystery:asset",
            "type": "unknown",
            "label": "asset",
            "severity": "none",
            "has_runtime_evidence": True,
            "is_entry_point": False,
            "is_crown_jewel": False,
            "metadata": {
                "kind": "mystery",
                "image": "distroless:latest",
                "kind_display": "Unknown",
            },
        },
        {
            "id": "s3:archive",
            "type": "s3_bucket",
            "label": "Archive Bucket",
            "severity": "none",
            "has_runtime_evidence": False,
            "is_entry_point": False,
            "is_crown_jewel": False,
            "metadata": {"kind_display": "S3 Bucket"},
        },
        {
            "id": "sa:prod:api",
            "type": "service_account",
            "label": "api",
            "severity": "none",
            "has_runtime_evidence": False,
            "is_entry_point": False,
            "is_crown_jewel": False,
            "metadata": {
                "namespace": "prod",
                "serviceAccount": "api-sa",
                "service_account": "api-sa",
                "kind_display": "Service Account",
            },
        },
    ]

    assert body["edges"] == [
        {
            "id": "edge-keep-1",
            "source": "sa:prod:api",
            "target": "s3:archive",
            "type": "assumes",
            "metadata": {
                "has_runtime_evidence": True,
                "reason": "The service account can assume this IAM role.",
            },
        },
        {
            "id": "edge-keep-2",
            "source": "s3:archive",
            "target": "mystery:asset",
            "type": "allows",
            "metadata": {
                "raw": 1,
                "reason": "A connectivity or permission relationship exists between these nodes.",
            },
        },
    ]

    assert body["paths"] == [
        {
            "id": "path-keep",
            "title": "api -> asset",
            "summary": "api to asset in 2 hops",
            "severity": "none",
            "evidence_count": 2,
            "node_ids": ["sa:prod:api", "s3:archive", "mystery:asset"],
            "edge_ids": ["edge-keep-1", "edge-keep-2"],
        }
    ]
