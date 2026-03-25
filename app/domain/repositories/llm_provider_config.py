from __future__ import annotations

from typing import List, Protocol, runtime_checkable


@runtime_checkable
class LLMProviderConfigRepository(Protocol):
    async def get_active(self, user_id: str) -> object | None:
        """Return the currently active saved provider config for the given user, if any."""
        ...

    async def get_by_provider(self, user_id: str, provider: str) -> object | None:
        """Return the saved provider config for the given user/provider pair, if any."""
        ...

    async def list_by_user(self, user_id: str) -> List[object]:
        """Return all saved provider configs for the given user."""
        ...

    async def upsert_by_user_and_provider(
        self,
        user_id: str,
        provider: str,
        *,
        api_key: str,
        is_active: bool,
        default_model: str | None = None,
    ) -> object:
        """Create or update the saved provider config for the given user/provider pair."""
        ...
