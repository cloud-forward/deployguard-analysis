from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.application.di import get_inventory_view_service, get_user_overview_service
from app.application.services.inventory_view_service import InventoryViewService
from app.models.schemas import (
    MeAssetInventoryListResponse,
    UserGroupListResponse,
    UserOverviewResponse,
    UserSummaryResponse,
)


router = APIRouter(prefix="/api/v1/me", tags=["Auth"])


@router.get("", response_model=UserSummaryResponse, summary="현재 사용자 프로필")
async def get_me(
    current_user: UserSummaryResponse = Depends(get_current_user),
) -> UserSummaryResponse:
    return current_user


@router.get("/overview", response_model=UserOverviewResponse, summary="현재 사용자 자산 개요")
async def get_my_overview(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> UserOverviewResponse:
    return await service.get_user_asset_summary(user_id=current_user.id)


@router.get("/assets", response_model=MeAssetInventoryListResponse, summary="현재 사용자 소유 자산 목록")
async def get_my_assets(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> MeAssetInventoryListResponse:
    return await service.list_user_assets(user_id=current_user.id)


@router.get("/groups", response_model=UserGroupListResponse, summary="현재 사용자 계산 그룹 목록")
async def get_my_groups(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: UserOverviewService = Depends(get_user_overview_service),
) -> UserGroupListResponse:
    return await service.list_groups(user_id=current_user.id)
