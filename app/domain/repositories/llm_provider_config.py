from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProviderConfigRepository(Protocol):
    async def get_active(self) -> object | None:
        """Return the currently active saved provider config, if any."""
        ...

    async def get_by_provider(self, provider: str) -> object | None:
        """Return the saved provider config for the given provider, if any."""
        ...
