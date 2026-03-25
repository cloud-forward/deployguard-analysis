from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.application.di import get_auth_service, get_llm_provider_config_service
from app.application.services.auth_service import AuthService
from app.application.services.llm_provider_config_service import LLMProviderConfigService
from app.main import app
from app.security.passwords import hash_password


@dataclass
class FakeProviderConfig:
    user_id: str
    provider: str
    api_key: str
    is_active: bool
    default_model: str | None
    created_at: datetime
    updated_at: datetime


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


class FakeLLMProviderConfigRepository:
    def __init__(self):
        self._store: dict[tuple[str, str], FakeProviderConfig] = {}

    async def list_by_user(self, user_id: str):
        return sorted(
            [config for (config_user_id, _provider), config in self._store.items() if config_user_id == user_id],
            key=lambda item: (item.updated_at, item.created_at),
            reverse=True,
        )

    async def upsert_by_user_and_provider(self, user_id: str, provider: str, *, api_key: str, is_active: bool, default_model: str | None = None):
        now = datetime.utcnow()
        if is_active:
            for (config_user_id, _provider), config in self._store.items():
                if config_user_id == user_id:
                    config.is_active = False
                    config.updated_at = now

        existing = self._store.get((user_id, provider))
        if existing is None:
            existing = FakeProviderConfig(
                user_id=user_id,
                provider=provider,
                api_key=api_key,
                is_active=is_active,
                default_model=default_model,
                created_at=now,
                updated_at=now,
            )
            self._store[(user_id, provider)] = existing
        else:
            existing.api_key = api_key
            existing.is_active = is_active
            existing.default_model = default_model
            existing.updated_at = now

        return existing


@pytest.fixture
def client():
    repo = FakeLLMProviderConfigRepository()
    service = LLMProviderConfigService(provider_config_repository=repo)
    app.dependency_overrides[get_llm_provider_config_service] = lambda: service
    auth_service = AuthService(
        user_repository=FakeUserRepository(
            [
                FakeUser(id="user-1", email="user-1@example.com", password_hash=hash_password("secret-password")),
                FakeUser(id="user-2", email="user-2@example.com", password_hash=hash_password("secret-password")),
            ]
        )
    )
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    with TestClient(app) as test_client:
        test_client.app_state["llm_provider_config_repo"] = repo
        yield test_client
    app.dependency_overrides.clear()


def _auth_headers(client: TestClient, user_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"{user_id}@example.com", "password": "secret-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_get_llm_provider_configs_returns_only_requesting_users_configs(client):
    repo = client.app_state["llm_provider_config_repo"]
    now = datetime.utcnow()
    repo._store[("user-1", "openai")] = FakeProviderConfig("user-1", "openai", "secret-1", True, "gpt-4o-mini", now, now)
    repo._store[("user-2", "xai")] = FakeProviderConfig("user-2", "xai", "secret-2", True, "grok-3-mini", now, now)

    response = client.get("/api/v1/llm/provider-configs", headers=_auth_headers(client, "user-1"))

    assert response.status_code == 200
    body = response.json()
    assert [item["provider"] for item in body["items"]] == ["openai"]


def test_put_llm_provider_config_creates_new_config_for_requesting_user(client):
    response = client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "user-1-openai-key", "is_active": True, "default_model": "gpt-4o-mini"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "openai"
    assert body["is_active"] is True
    assert body["default_model"] == "gpt-4o-mini"
    assert body["has_api_key"] is True


def test_put_llm_provider_config_updates_existing_config_for_same_user_and_provider(client):
    client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "old-key", "is_active": False, "default_model": "gpt-4o-mini"},
    )

    response = client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "new-key", "is_active": True, "default_model": "gpt-4o-mini"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "openai"
    assert body["is_active"] is True


def test_put_for_one_user_does_not_overwrite_another_users_config(client):
    client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-2"),
        json={"api_key": "user-2-key", "is_active": True, "default_model": "gpt-4o-mini"},
    )

    client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "user-1-key", "is_active": False, "default_model": "gpt-4o-mini"},
    )

    response = client.get("/api/v1/llm/provider-configs", headers=_auth_headers(client, "user-2"))

    assert response.status_code == 200
    assert response.json()["items"][0]["provider"] == "openai"
    assert response.json()["items"][0]["is_active"] is True


def test_setting_one_config_active_deactivates_same_users_other_active_config(client):
    client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "openai-key", "is_active": True, "default_model": "gpt-4o-mini"},
    )

    client.put(
        "/api/v1/llm/provider-configs/xai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "xai-key", "is_active": True, "default_model": "grok-3-mini"},
    )

    response = client.get("/api/v1/llm/provider-configs", headers=_auth_headers(client, "user-1"))

    assert response.status_code == 200
    items = {item["provider"]: item for item in response.json()["items"]}
    assert items["xai"]["is_active"] is True
    assert items["openai"]["is_active"] is False


def test_raw_api_key_is_not_exposed_in_get_response(client):
    client.put(
        "/api/v1/llm/provider-configs/openai",
        headers=_auth_headers(client, "user-1"),
        json={"api_key": "secret-api-key", "is_active": True, "default_model": "gpt-4o-mini"},
    )

    response = client.get("/api/v1/llm/provider-configs", headers=_auth_headers(client, "user-1"))

    assert response.status_code == 200
    body = response.json()
    assert "api_key" not in body["items"][0]
    assert body["items"][0]["has_api_key"] is True


def test_llm_provider_config_routes_require_jwt_and_ignore_x_user_id_only(client):
    response = client.get("/api/v1/llm/provider-configs", headers={"X-User-Id": "user-1"})

    assert response.status_code == 401
