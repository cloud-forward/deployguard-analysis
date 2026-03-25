from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.application.di import get_auth_service
from app.application.services.auth_service import AuthService
from app.main import app
from app.models.schemas import UserSummaryResponse
from app.security.passwords import hash_password


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    is_active: bool = True


class FakeUserRepository:
    def __init__(self, users: list[FakeUser]):
        self._users_by_email = {user.email: user for user in users}
        self._users_by_id = {user.id: user for user in users}

    async def get_by_email(self, email: str):
        return self._users_by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._users_by_id.get(user_id)


protected_router = APIRouter()


@protected_router.get("/_test/current-user", response_model=UserSummaryResponse)
async def read_current_user(current_user: UserSummaryResponse = Depends(get_current_user)):
    return current_user


app.include_router(protected_router)


def _build_client():
    user = FakeUser(
        id="user-1",
        email="user@example.com",
        password_hash=hash_password("secret-password"),
        is_active=True,
    )
    auth_service = AuthService(user_repository=FakeUserRepository([user]))
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    return TestClient(app)


def test_login_succeeds_with_correct_email_and_password():
    app.dependency_overrides.clear()
    with _build_client() as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "secret-password"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["id"] == "user-1"
    assert body["user"]["email"] == "user@example.com"


def test_login_fails_with_wrong_password():
    app.dependency_overrides.clear()
    with _build_client() as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "wrong-password"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 401


def test_login_fails_with_nonexistent_user():
    app.dependency_overrides.clear()
    with _build_client() as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "missing@example.com", "password": "secret-password"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 401


def test_get_current_user_succeeds_with_valid_token():
    app.dependency_overrides.clear()
    with _build_client() as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "secret-password"},
        )
        token = login.json()["access_token"]
        response = client.get(
            "/_test/current-user",
            headers={"Authorization": f"Bearer {token}"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["id"] == "user-1"


def test_get_current_user_fails_with_invalid_token():
    app.dependency_overrides.clear()
    with _build_client() as client:
        response = client.get(
            "/_test/current-user",
            headers={"Authorization": "Bearer invalid-token"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 401


def test_get_me_returns_authenticated_user_profile():
    app.dependency_overrides.clear()
    with _build_client() as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "secret-password"},
        )
        token = login.json()["access_token"]
        response = client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "id": "user-1",
        "email": "user@example.com",
        "is_active": True,
    }


def test_get_me_requires_jwt():
    app.dependency_overrides.clear()
    with _build_client() as client:
        response = client.get("/api/v1/me")
    app.dependency_overrides.clear()

    assert response.status_code == 401
