from __future__ import annotations

from datetime import datetime
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.application.di import get_cluster_service
from app.application.services.cluster_service import ClusterService
from app.main import app


class _FakeClusterRecord:
    def __init__(
        self,
        id,
        name,
        cluster_type,
        description,
        api_token,
        created_at,
        updated_at,
        aws_account_id=None,
        aws_role_arn=None,
        aws_region=None,
    ):
        self.id = id
        self.name = name
        self.cluster_type = cluster_type
        self.description = description
        self.api_token = api_token
        self.created_at = created_at
        self.updated_at = updated_at
        self.aws_account_id = aws_account_id
        self.aws_role_arn = aws_role_arn
        self.aws_region = aws_region


class FakeClusterRepository:
    def __init__(self):
        self._store: dict = {}
        self._counter = 0

    def _make_id(self):
        self._counter += 1
        return f"cluster-{self._counter}"

    async def create(
        self,
        name: str,
        cluster_type: str,
        description: Optional[str] = None,
        api_token: Optional[str] = None,
        aws_account_id: Optional[str] = None,
        aws_role_arn: Optional[str] = None,
        aws_region: Optional[str] = None,
    ):
        record = _FakeClusterRecord(
            id=self._make_id(),
            name=name,
            cluster_type=cluster_type,
            description=description,
            api_token=api_token,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            aws_account_id=aws_account_id,
            aws_role_arn=aws_role_arn,
            aws_region=aws_region,
        )
        self._store[record.id] = record
        return record

    async def get_by_id(self, cluster_id: str):
        return self._store.get(cluster_id)

    async def get_by_name(self, name: str):
        for r in self._store.values():
            if r.name == name:
                return r
        return None

    async def list_all(self):
        return list(self._store.values())

    async def update(self, cluster_id: str, **kwargs):
        record = self._store.get(cluster_id)
        if not record:
            return None
        for k, v in kwargs.items():
            if hasattr(record, k):
                setattr(record, k, v)
        record.updated_at = datetime.utcnow()
        return record

    async def delete(self, cluster_id: str) -> bool:
        if cluster_id in self._store:
            del self._store[cluster_id]
            return True
        return False


@pytest.fixture
def client():
    repo = FakeClusterRepository()
    service = ClusterService(cluster_repository=repo)
    app.dependency_overrides[get_cluster_service] = lambda: service
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def created_cluster(client):
    resp = client.post("/api/v1/clusters", json={"name": "base-cluster", "cluster_type": "eks"})
    assert resp.status_code == 201
    return resp.json()


def test_create_cluster(client):
    resp = client.post("/api/v1/clusters", json={"name": "my-cluster", "cluster_type": "eks", "description": "desc"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "my-cluster"
    assert data["cluster_type"] == "eks"
    assert data["description"] == "desc"
    assert "id" in data
    assert "api_token" in data
    assert data["api_token"]
    assert data["onboarding"]["installation_method"] == "helm"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_values"]["imagePullSecret"] == "deployguard-registry"


def test_create_cluster_without_description(client):
    resp = client.post("/api/v1/clusters", json={"name": "no-desc", "cluster_type": "self-managed"})
    assert resp.status_code == 201
    assert resp.json()["description"] is None


def test_create_cluster_with_aws_type(client):
    resp = client.post("/api/v1/clusters", json={"name": "aws-cluster", "cluster_type": "aws"})
    assert resp.status_code == 201
    data = resp.json()
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


def test_create_cluster_with_self_managed_type_uses_helm_onboarding(client):
    resp = client.post("/api/v1/clusters", json={"name": "self-managed-cluster", "cluster_type": "self-managed"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["cluster_type"] == "self-managed"
    assert data["onboarding"]["installation_method"] == "helm"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_values"]["imagePullSecret"] == "deployguard-registry"


def test_create_cluster_duplicate_name_rejected(client, created_cluster):
    resp = client.post("/api/v1/clusters", json={"name": created_cluster["name"], "cluster_type": "eks"})
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"]


def test_create_cluster_invalid_type(client):
    resp = client.post("/api/v1/clusters", json={"name": "bad-type", "cluster_type": "gke"})
    assert resp.status_code == 422


def test_create_cluster_missing_name(client):
    resp = client.post("/api/v1/clusters", json={"cluster_type": "eks"})
    assert resp.status_code == 422


def test_create_cluster_missing_type(client):
    resp = client.post("/api/v1/clusters", json={"name": "no-type"})
    assert resp.status_code == 422


def test_get_cluster_by_id(client, created_cluster):
    resp = client.get(f"/api/v1/clusters/{created_cluster['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == created_cluster["id"]
    assert resp.json()["name"] == created_cluster["name"]
    assert "api_token" not in resp.json()


def test_get_cluster_not_found(client):
    resp = client.get("/api/v1/clusters/nonexistent-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_list_clusters(client):
    client.post("/api/v1/clusters", json={"name": "c1", "cluster_type": "eks"})
    client.post("/api/v1/clusters", json={"name": "c2", "cluster_type": "self-managed"})
    resp = client.get("/api/v1/clusters")
    assert resp.status_code == 200
    names = [c["name"] for c in resp.json()]
    assert "c1" in names
    assert "c2" in names
    assert all("api_token" not in c for c in resp.json())


def test_list_clusters_empty(client):
    resp = client.get("/api/v1/clusters")
    assert resp.status_code == 200
    assert resp.json() == []


def test_update_cluster_description(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"description": "new desc"},
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "new desc"


def test_update_cluster_type(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "self-managed"},
    )
    assert resp.status_code == 200
    assert resp.json()["cluster_type"] == "self-managed"


def test_update_cluster_type_to_aws(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "aws"},
    )
    assert resp.status_code == 200
    assert resp.json()["cluster_type"] == "aws"


def test_update_cluster_invalid_type(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "invalid"},
    )
    assert resp.status_code == 422


def test_update_cluster_not_found(client):
    resp = client.patch("/api/v1/clusters/ghost-id", json={"description": "x"})
    assert resp.status_code == 404


def test_delete_cluster(client, created_cluster):
    resp = client.delete(f"/api/v1/clusters/{created_cluster['id']}")
    assert resp.status_code == 204
    assert client.get(f"/api/v1/clusters/{created_cluster['id']}").status_code == 404


def test_delete_cluster_not_found(client):
    resp = client.delete("/api/v1/clusters/ghost-id")
    assert resp.status_code == 404


def test_openapi_cluster_create_documents_token_issuance(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()

    post_clusters = spec["paths"]["/api/v1/clusters"]["post"]
    description = post_clusters["description"]
    assert "클러스터 등록 시 스캐너 인증용 API 토큰이 함께 발급" in description
    assert "Helm 설치" in description
    assert "1회 반환" in description
    assert "`aws`" in description

    create_schema_name = post_clusters["responses"]["201"]["content"]["application/json"]["schema"]["$ref"].split("/")[-1]
    create_props = spec["components"]["schemas"][create_schema_name]["properties"]
    assert "api_token" in create_props
    assert "onboarding" in create_props

    list_schema_name = (
        spec["paths"]["/api/v1/clusters"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["items"]["$ref"].split("/")[-1]
    )
    list_props = spec["components"]["schemas"][list_schema_name]["properties"]
    assert "api_token" not in list_props

    detail_schema_name = (
        spec["paths"]["/api/v1/clusters/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].split("/")[-1]
    )
    detail_props = spec["components"]["schemas"][detail_schema_name]["properties"]
    assert "api_token" not in detail_props
