from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.application.services.auth_service import AuthService
from app.security.passwords import hash_password


@dataclass
class FakeUser:
    id: str
    email: str
    password_hash: str
    is_active: bool = True


class FakeUserRepository:
    def __init__(self, *, by_email=None, by_id=None):
        self._by_email = by_email or {}
        self._by_id = by_id or {}

    async def get_by_email(self, email: str):
        return self._by_email.get(email)

    async def get_by_id(self, user_id: str):
        return self._by_id.get(user_id)


@pytest.mark.asyncio
async def test_authenticate_user_succeeds_with_valid_credentials():
    user = FakeUser(
        id="user-1",
        email="user@example.com",
        password_hash=hash_password("secret-password"),
    )
    service = AuthService(user_repository=FakeUserRepository(by_email={"user@example.com": user}))

    result = await service.authenticate_user("user@example.com", "secret-password")

    assert result is not None
    assert result.id == "user-1"


@pytest.mark.asyncio
async def test_authenticate_user_returns_none_for_wrong_password():
    user = FakeUser(
        id="user-1",
        email="user@example.com",
        password_hash=hash_password("secret-password"),
    )
    service = AuthService(user_repository=FakeUserRepository(by_email={"user@example.com": user}))

    result = await service.authenticate_user("user@example.com", "wrong-password")

    assert result is None


@pytest.mark.asyncio
async def test_authenticate_user_returns_none_for_unknown_user():
    service = AuthService(user_repository=FakeUserRepository())

    result = await service.authenticate_user("missing@example.com", "secret-password")

    assert result is None
