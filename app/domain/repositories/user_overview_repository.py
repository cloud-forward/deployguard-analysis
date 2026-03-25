from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.models.schemas import UserAssetListResponse, UserOverviewResponse


@runtime_checkable
class UserOverviewRepository(Protocol):
    async def get_overview(self, user_id: str) -> UserOverviewResponse:
        """Return user-scoped aggregated overview counts."""
        ...

    async def list_assets(self, user_id: str) -> UserAssetListResponse:
        """Return user-scoped owned asset list."""
        ...
