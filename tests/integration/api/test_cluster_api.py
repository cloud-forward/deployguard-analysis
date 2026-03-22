import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.di import get_attack_graph_service, get_cluster_service
from app.application.services.attack_graph_service import AttackGraphService
from app.application.services.cluster_service import ClusterService
from app.gateway.db.base import Base
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository
from app.main import app

def test_create_cluster(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "test-cluster",
            "cluster_type": "eks",
            "description": "A test cluster"
        }
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
        }
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
        }
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
        }
    )
    assert response.status_code == 422

def test_list_clusters(client):
    client.post("/api/v1/clusters", json={"name": "c1", "cluster_type": "eks"})
    client.post("/api/v1/clusters", json={"name": "c2", "cluster_type": "self-managed"})
    
    response = client.get("/api/v1/clusters")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2
    assert all("api_token" not in c for c in data)

def test_get_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "get-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.get(f"/api/v1/clusters/{cluster_id}")
    assert response.status_code == 200
    assert response.json()["name"] == "get-me"
    assert "api_token" not in response.json()

def test_update_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "update-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.patch(
        f"/api/v1/clusters/{cluster_id}",
        json={"description": "updated description", "cluster_type": "self-managed"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["description"] == "updated description"
    assert data["cluster_type"] == "self-managed"

def test_delete_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "delete-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    del_resp = client.delete(f"/api/v1/clusters/{cluster_id}")
    assert del_resp.status_code == 204
    
    get_resp = client.get(f"/api/v1/clusters/{cluster_id}")
    assert get_resp.status_code == 404


def test_create_cluster_token_is_persisted_for_auth_lookup():
    app.dependency_overrides.clear()
    name = f"persist-{uuid4().hex[:8]}"
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": name, "cluster_type": "eks"},
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
                graph_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                edge_type TEXT,
                metadata TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE attack_paths (
                graph_id TEXT NOT NULL,
                path_id TEXT NOT NULL,
                title TEXT,
                risk_level TEXT,
                node_ids TEXT,
                edge_ids TEXT
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
        create_resp = client.post("/api/v1/clusters", json={"name": "graph-cluster", "cluster_type": "eks"})
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
        await session.execute(text("INSERT INTO graph_snapshots (id) VALUES (:id)"), {"id": graph_id})
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
                INSERT INTO graph_edges (graph_id, edge_id, source, target, edge_type, metadata)
                VALUES
                    (:graph_id, 'edge-1', 'ingress:prod:web', 'pod:prod:api', 'allows', '{"protocol":"http"}'),
                    (:graph_id, 'edge-2', 'pod:prod:api', 's3:prod-secrets', 'accesses', NULL)
                """
            ),
            {"graph_id": graph_id},
        )
        await session.execute(
            text(
                """
                INSERT INTO attack_paths (graph_id, path_id, title, risk_level, node_ids, edge_ids)
                VALUES (:graph_id, 'path-1', 'Internet to secrets', 'critical',
                        '["ingress:prod:web","pod:prod:api","s3:prod-secrets"]',
                        '["edge-1","edge-2"]')
                """
            ),
            {"graph_id": graph_id},
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
        "title": "Internet to secrets",
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
        await session.execute(text("INSERT INTO graph_snapshots (id) VALUES (:id)"), {"id": graph_id})
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
                INSERT INTO graph_edges (graph_id, edge_id, source, target, edge_type, metadata)
                VALUES
                    (:graph_id, 'edge-keep-1', 'sa:prod:api', 's3:archive', 'service_account_assumes_iam_role', :edge_keep_1_metadata),
                    (:graph_id, 'edge-keep-2', 's3:archive', 'mystery:asset', 'totally_custom', :edge_keep_2_metadata),
                    (:graph_id, 'edge-drop', 'ghost:src', 's3:archive', 'allows', NULL)
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
                INSERT INTO attack_paths (graph_id, path_id, title, risk_level, node_ids, edge_ids)
                VALUES
                    (:graph_id, 'path-keep', '', 'urgent',
                        '["sa:prod:api","s3:archive","mystery:asset"]',
                        '["edge-keep-1","edge-keep-2"]'),
                    (:graph_id, 'path-drop-missing-node', 'bad node path', 'high',
                        '["sa:prod:api","ghost:node"]',
                        '["edge-keep-1"]'),
                    (:graph_id, 'path-drop-missing-edge', 'bad edge path', 'low',
                        '["sa:prod:api","s3:archive"]',
                        '["edge-drop"]')
                """
            ),
            {"graph_id": graph_id},
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
