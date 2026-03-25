from __future__ import annotations

from app.security.passwords import verify_password


class AuthService:
    def __init__(self, user_repository) -> None:
        self._users = user_repository

    async def authenticate_user(self, email: str, password: str):
        normalized_email = email.strip().lower()
        user = await self._users.get_by_email(normalized_email)
        if user is None or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    async def get_user_by_id(self, user_id: str):
        user = await self._users.get_by_id(user_id)
        if user is None or not user.is_active:
            return None
        return user
