from __future__ import annotations

from app.domain.repositories.user_overview_repository import UserOverviewRepository
from app.models.schemas import UserAssetListResponse, UserGroupListResponse, UserOverviewResponse


class UserOverviewService:
    def __init__(self, overview_repository: UserOverviewRepository) -> None:
        self._overview_repository = overview_repository

    async def get_overview(self, user_id: str) -> UserOverviewResponse:
        return await self._overview_repository.get_overview(user_id)

    async def list_assets(self, user_id: str) -> UserAssetListResponse:
        return await self._overview_repository.list_assets(user_id)

    async def list_groups(self, user_id: str) -> UserGroupListResponse:
        return await self._overview_repository.list_groups(user_id)
