from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient

from app.application.di import get_auth_service
from app.application.services.auth_service import AuthService
from app.main import app
from app.security.passwords import hash_password, verify_password


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    name: str | None = None
    is_active: bool = True


class FakeUserRepository:
    def __init__(self):
        self._by_email: dict[str, FakeUser] = {}
        self._by_id: dict[str, FakeUser] = {}
        self._next_id: int = 1

    async def get_by_email(self, email: str):
        return self._by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._by_id.get(user_id)

    async def create_user(self, email: str, password_hash: str, name: str | None = None) -> FakeUser:
        user_id = f"new-user-{self._next_id}"
        self._next_id += 1
        user = FakeUser(id=user_id, email=email, password_hash=password_hash, name=name)
        self._by_email[email] = user
        self._by_id[user_id] = user
        return user


def _build_client(repo: FakeUserRepository | None = None):
    if repo is None:
        repo = FakeUserRepository()
    auth_service = AuthService(user_repository=repo)
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    return TestClient(app), repo


def test_signup_succeeds_with_new_email():
    app.dependency_overrides.clear()
    client, _ = _build_client()
    with client:
        response = client.post(
            "/api/v1/auth/signup",
            json={"email": "new@example.com", "password": "strongpass"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "new@example.com"
    assert body["user"]["is_active"] is True
    assert "id" in body["user"]


def test_signup_stores_hashed_password_not_plaintext():
    app.dependency_overrides.clear()
    repo = FakeUserRepository()
    client, repo = _build_client(repo)
    with client:
        client.post(
            "/api/v1/auth/signup",
            json={"email": "hash@example.com", "password": "mypassword"},
        )
    app.dependency_overrides.clear()

    stored_user = repo._by_email.get("hash@example.com")
    assert stored_user is not None
    assert stored_user.password_hash != "mypassword"
    assert verify_password("mypassword", stored_user.password_hash)


def test_signup_rejects_duplicate_email():
    app.dependency_overrides.clear()
    repo = FakeUserRepository()
    client, _ = _build_client(repo)
    with client:
        client.post(
            "/api/v1/auth/signup",
            json={"email": "dup@example.com", "password": "firstpass"},
        )
        response = client.post(
            "/api/v1/auth/signup",
            json={"email": "dup@example.com", "password": "secondpass"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 409


def test_signup_stores_name():
    app.dependency_overrides.clear()
    repo = FakeUserRepository()
    client, repo = _build_client(repo)
    with client:
        response = client.post(
            "/api/v1/auth/signup",
            json={"email": "named@example.com", "password": "strongpass", "name": "Alice"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["name"] == "Alice"
    stored = repo._by_email.get("named@example.com")
    assert stored is not None
    assert stored.name == "Alice"


def test_signup_name_optional():
    app.dependency_overrides.clear()
    client, _ = _build_client()
    with client:
        response = client.post(
            "/api/v1/auth/signup",
            json={"email": "noname@example.com", "password": "strongpass"},
        )
    app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["user"]["name"] is None


def test_login_works_after_signup():
    app.dependency_overrides.clear()
    repo = FakeUserRepository()
    client, _ = _build_client(repo)
    with client:
        client.post(
            "/api/v1/auth/signup",
            json={"email": "login@example.com", "password": "mypassword"},
        )
        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": "login@example.com", "password": "mypassword"},
        )
    app.dependency_overrides.clear()

    assert login_response.status_code == 200
    body = login_response.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body
    assert body["user"]["email"] == "login@example.com"
