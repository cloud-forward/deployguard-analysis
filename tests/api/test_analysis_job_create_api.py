from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.application.di import get_analysis_service, get_auth_service
from app.application.services.auth_service import AuthService
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
def analysis_service():
    service = AsyncMock()
    service.create_analysis_job.return_value = {
        "job_id": "job-123",
        "status": "accepted",
        "message": "Analysis job created",
    }
    return service


@pytest.fixture
def client(analysis_service):
    app.dependency_overrides[get_analysis_service] = lambda: analysis_service
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _auth_headers(client: TestClient, user_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestAnalysisJobCreateApi:
    def test_create_analysis_job_without_cluster_id(self, client, analysis_service):
        response = client.post(
            "/api/v1/analysis/jobs",
            json={"k8s_scan_id": "k8s-1", "image_scan_id": "img-1"},
            headers=_auth_headers(client, "user-1"),
        )

        assert response.status_code == 202
        analysis_service.create_analysis_job.assert_awaited_once_with(
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
            user_id="user-1",
        )

    def test_create_analysis_job_requires_jwt_and_ignores_x_user_id_only(self, client, analysis_service):
        response = client.post(
            "/api/v1/analysis/jobs",
            json={"k8s_scan_id": "k8s-1"},
            headers={"X-User-Id": "user-1"},
        )

        assert response.status_code == 401
        analysis_service.create_analysis_job.assert_not_called()
