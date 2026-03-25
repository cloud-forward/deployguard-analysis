from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.application.di import (
    get_auth_service,
    get_attack_graph_service,
    get_cluster_service,
    get_recommendation_explanation_service,
)
from app.application.services.auth_service import AuthService
from app.models.schemas import (
    ClusterUpdateRequest,
    RecommendationExplanationResponse,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationDetailResponse,
)
from app.application.services.cluster_service import ClusterService
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
        user_id=None,
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
        self.user_id = user_id
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
        user_id: Optional[str] = None,
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
            user_id=user_id,
            aws_account_id=aws_account_id,
            aws_role_arn=aws_role_arn,
            aws_region=aws_region,
        )
        self._store[record.id] = record
        return record

    async def get_by_id(self, cluster_id: str, user_id: Optional[str] = None):
        record = self._store.get(cluster_id)
        if record is None:
            return None
        if user_id is not None and record.user_id != user_id:
            return None
        return record

    async def get_by_name(self, name: str):
        for r in self._store.values():
            if r.name == name:
                return r
        return None

    async def list_all(self, user_id: str):
        return [record for record in self._store.values() if record.user_id == user_id]

    async def update(self, cluster_id: str, user_id: Optional[str] = None, **kwargs):
        record = self._store.get(cluster_id)
        if not record:
            return None
        if user_id is not None and record.user_id != user_id:
            return None
        for k, v in kwargs.items():
            if hasattr(record, k):
                setattr(record, k, v)
        record.updated_at = datetime.utcnow()
        return record

    async def delete(self, cluster_id: str, user_id: Optional[str] = None) -> bool:
        record = self._store.get(cluster_id)
        if record is None:
            return False
        if user_id is not None and record.user_id != user_id:
            return False
        del self._store[cluster_id]
        return True


@pytest.fixture
def client():
    repo = FakeClusterRepository()
    service = ClusterService(cluster_repository=repo)
    app.dependency_overrides[get_cluster_service] = lambda: service
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-42", email="user-42@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as c:
        c.app_state["cluster_repo"] = repo
        yield c
    app.dependency_overrides.clear()


def _auth_headers(client: TestClient, user_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def created_cluster(client):
    resp = client.post("/api/v1/clusters", json={"name": "base-cluster", "cluster_type": "eks"}, headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 201
    return resp.json()


def test_create_cluster(client):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "my-cluster", "cluster_type": "eks", "description": "desc"},
        headers=_auth_headers(client, "user-1"),
    )
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
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "no-desc", "cluster_type": "self-managed"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 201
    assert resp.json()["description"] is None


def test_create_cluster_with_aws_type(client):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "aws-cluster", "cluster_type": "aws"},
        headers=_auth_headers(client, "user-1"),
    )
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
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "self-managed-cluster", "cluster_type": "self-managed"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["cluster_type"] == "self-managed"
    assert data["onboarding"]["installation_method"] == "helm"
    assert data["onboarding"]["required_values"]["clusterId"] == data["id"]
    assert data["onboarding"]["required_values"]["apiToken"] == data["api_token"]
    assert data["onboarding"]["required_values"]["imagePullSecret"] == "deployguard-registry"


def test_create_cluster_duplicate_name_rejected(client, created_cluster):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": created_cluster["name"], "cluster_type": "eks"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"]


def test_create_cluster_invalid_type(client):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "bad-type", "cluster_type": "gke"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 422


def test_create_cluster_missing_name(client):
    resp = client.post("/api/v1/clusters", json={"cluster_type": "eks"}, headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 422


def test_create_cluster_missing_type(client):
    resp = client.post("/api/v1/clusters", json={"name": "no-type"}, headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 422


def test_create_cluster_uses_jwt_current_user_and_stores_user_id(client):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "owned-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-42"),
    )

    assert resp.status_code == 201
    cluster_id = resp.json()["id"]
    stored = client.app_state["cluster_repo"]._store[cluster_id]
    assert stored.user_id == "user-42"


def test_get_cluster_by_id(client, created_cluster):
    resp = client.get(f"/api/v1/clusters/{created_cluster['id']}", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 200
    assert resp.json()["id"] == created_cluster["id"]
    assert resp.json()["name"] == created_cluster["name"]
    assert "api_token" not in resp.json()


def test_get_cluster_not_found(client):
    resp = client.get("/api/v1/clusters/nonexistent-id", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_cluster_returns_not_found_for_other_users_cluster(client):
    create_resp = client.post(
        "/api/v1/clusters",
        json={"name": "other-users-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-2"),
    )

    resp = client.get(
        f"/api/v1/clusters/{create_resp.json()['id']}",
        headers=_auth_headers(client, "user-1"),
    )

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_list_clusters(client):
    client.post("/api/v1/clusters", json={"name": "c1", "cluster_type": "eks"}, headers=_auth_headers(client, "user-1"))
    client.post("/api/v1/clusters", json={"name": "c2", "cluster_type": "self-managed"}, headers=_auth_headers(client, "user-1"))
    resp = client.get("/api/v1/clusters", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 200
    names = [c["name"] for c in resp.json()]
    assert "c1" in names
    assert "c2" in names
    assert all("api_token" not in c for c in resp.json())


def test_list_clusters_empty(client):
    resp = client.get("/api/v1/clusters", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_clusters_uses_x_user_id_and_returns_only_owned_clusters(client):
    client.post(
        "/api/v1/clusters",
        json={"name": "user-1-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-1"),
    )
    client.post(
        "/api/v1/clusters",
        json={"name": "user-2-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-2"),
    )

    resp = client.get("/api/v1/clusters", headers=_auth_headers(client, "user-1"))

    assert resp.status_code == 200
    assert [cluster["name"] for cluster in resp.json()] == ["user-1-cluster"]


def test_update_cluster_description(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"description": "new desc"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "new desc"


def test_update_cluster_type(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "self-managed"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 200
    assert resp.json()["cluster_type"] == "self-managed"


def test_update_cluster_type_to_aws(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "aws"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 200
    assert resp.json()["cluster_type"] == "aws"


def test_update_cluster_invalid_type(client, created_cluster):
    resp = client.patch(
        f"/api/v1/clusters/{created_cluster['id']}",
        json={"cluster_type": "invalid"},
        headers=_auth_headers(client, "user-1"),
    )
    assert resp.status_code == 422


def test_update_cluster_not_found(client):
    resp = client.patch("/api/v1/clusters/ghost-id", json={"description": "x"}, headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 404


def test_update_cluster_returns_not_found_for_other_users_cluster(client):
    create_resp = client.post(
        "/api/v1/clusters",
        json={"name": "other-users-update-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-2"),
    )

    resp = client.patch(
        f"/api/v1/clusters/{create_resp.json()['id']}",
        json={"description": "should-not-update"},
        headers=_auth_headers(client, "user-1"),
    )

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_delete_cluster_returns_not_found_for_other_users_cluster(client):
    create_resp = client.post(
        "/api/v1/clusters",
        json={"name": "other-users-delete-cluster", "cluster_type": "eks"},
        headers=_auth_headers(client, "user-2"),
    )

    resp = client.delete(
        f"/api/v1/clusters/{create_resp.json()['id']}",
        headers=_auth_headers(client, "user-1"),
    )

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


class FakeAttackGraphService:
    async def get_remediation_recommendation_detail(self, cluster_id: str, recommendation_id: str):
        return RemediationRecommendationDetailEnvelopeResponse(
            cluster_id=cluster_id,
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=RemediationRecommendationDetailResponse(
                recommendation_id=recommendation_id,
                recommendation_rank=0,
                edge_source="secret:prod:db-creds",
                edge_target="rds:prod-db",
                edge_type="secret_contains_credentials",
                fix_type="rotate_credentials",
                fix_description="Rotate exposed database credentials.",
                blocked_path_ids=["path-db"],
                blocked_path_indices=[4],
                fix_cost=1.3,
                edge_score=0.9,
                covered_risk=0.9,
                cumulative_risk_reduction=0.9,
                metadata={"secret_type": "db"},
            ),
        )

    async def get_attack_graph(self, cluster_id: str, user_id: str | None = None):
        return {"cluster_id": cluster_id, "analysis_run_id": None, "generated_at": None, "nodes": [], "edges": [], "paths": []}

    async def get_attack_paths(self, cluster_id: str, user_id: str | None = None):
        return {"cluster_id": cluster_id, "analysis_run_id": None, "generated_at": None, "items": []}

    async def get_attack_path_detail(self, cluster_id: str, path_id: str, user_id: str | None = None):
        return {"cluster_id": cluster_id, "analysis_run_id": None, "generated_at": None, "path": None}


class FakeRecommendationExplanationService:
    def __init__(self):
        self.calls = []

    async def explain_recommendation(self, *, cluster_id: str, recommendation_id: str, user_id: str, request):
        self.calls.append((cluster_id, recommendation_id, user_id, request))
        return RecommendationExplanationResponse(
            cluster_id=cluster_id,
            recommendation_id=recommendation_id,
            explanation_status="base_only",
            used_llm=False,
            base_explanation="Base explanation.",
            final_explanation="Base explanation.",
            provider=request.provider.value if request.provider is not None else None,
            model=request.model,
            fallback_reason="provider_not_configured",
        )


def test_post_remediation_recommendation_explanation_manual_endpoint():
    repo = FakeClusterRepository()
    cluster_service = ClusterService(cluster_repository=repo)
    explanation_service = FakeRecommendationExplanationService()
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_cluster_service] = lambda: cluster_service
    app.dependency_overrides[get_recommendation_explanation_service] = lambda: explanation_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": "explain-cluster", "cluster_type": "eks"},
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_resp.json()["id"]
        response = client.post(
            f"/api/v1/clusters/{cluster_id}/remediation-recommendations/rotate-credentials-1/explanation",
            json={"provider": "openai", "model": "gpt-4o-mini"},
            headers=_auth_headers(client, "user-1"),
        )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == cluster_id
    assert body["recommendation_id"] == "rotate-credentials-1"
    assert body["explanation_status"] == "base_only"
    assert len(explanation_service.calls) == 1
    assert explanation_service.calls[0][2] == "user-1"


def test_remediation_explanation_route_requires_jwt_and_ignores_x_user_id_only():
    repo = FakeClusterRepository()
    cluster_service = ClusterService(cluster_repository=repo)
    explanation_service = FakeRecommendationExplanationService()
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_cluster_service] = lambda: cluster_service
    app.dependency_overrides[get_recommendation_explanation_service] = lambda: explanation_service
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": "explain-auth-cluster", "cluster_type": "eks"},
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_resp.json()["id"]
        response = client.post(
            f"/api/v1/clusters/{cluster_id}/remediation-recommendations/rotate-credentials-1/explanation",
            json={},
            headers={"X-User-Id": "user-1"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 401
    assert explanation_service.calls == []


def test_existing_remediation_detail_get_behavior_remains_unchanged():
    repo = FakeClusterRepository()
    cluster_service = ClusterService(cluster_repository=repo)
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_cluster_service] = lambda: cluster_service
    app.dependency_overrides[get_attack_graph_service] = lambda: FakeAttackGraphService()
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": "detail-cluster", "cluster_type": "eks"},
            headers=_auth_headers(client, "user-1"),
        )
        cluster_id = create_resp.json()["id"]
        response = client.get(
            f"/api/v1/clusters/{cluster_id}/remediation-recommendations/rotate-credentials-1"
        )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["cluster_id"] == cluster_id
    assert body["recommendation"]["recommendation_id"] == "rotate-credentials-1"
    assert body["recommendation"]["fix_description"] == "Rotate exposed database credentials."


def test_delete_cluster(client, created_cluster):
    resp = client.delete(f"/api/v1/clusters/{created_cluster['id']}", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 204
    assert client.get(f"/api/v1/clusters/{created_cluster['id']}", headers=_auth_headers(client, "user-1")).status_code == 404


def test_delete_cluster_not_found(client):
    resp = client.delete("/api/v1/clusters/ghost-id", headers=_auth_headers(client, "user-1"))
    assert resp.status_code == 404


def test_cluster_routes_require_jwt_and_ignore_x_user_id_only(client):
    resp = client.get("/api/v1/clusters", headers={"X-User-Id": "user-1"})
    assert resp.status_code == 401


def test_cluster_create_requires_jwt_and_ignores_x_user_id_only(client):
    resp = client.post(
        "/api/v1/clusters",
        json={"name": "jwt-required", "cluster_type": "eks"},
        headers={"X-User-Id": "user-1"},
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/api/v1/clusters/cluster-1/attack-graph", "get"),
        ("/api/v1/clusters/cluster-1/attack-paths", "get"),
        ("/api/v1/clusters/cluster-1/attack-paths/path-1", "get"),
    ],
)
def test_attack_graph_and_path_routes_require_jwt_and_ignore_x_user_id_only(path, method):
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_attack_graph_service] = lambda: FakeAttackGraphService()
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as client:
        response = getattr(client, method)(path, headers={"X-User-Id": "user-1"})
    app.dependency_overrides.clear()

    assert response.status_code == 401


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
