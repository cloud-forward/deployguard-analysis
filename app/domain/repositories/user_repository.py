from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> object | None:
        """Return the user for the given email, if any."""
        ...

    async def get_by_id(self, user_id: str) -> object | None:
        """Return the user for the given id, if any."""
        ...

    async def create_user(self, email: str, password_hash: str) -> object:
        """Create and return a new user with the given email and password_hash."""
        ...
