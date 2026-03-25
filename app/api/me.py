from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.application.di import get_user_overview_service
from app.application.services.user_overview_service import UserOverviewService
from app.models.schemas import UserAssetListResponse, UserGroupListResponse, UserOverviewResponse, UserSummaryResponse


router = APIRouter(prefix="/api/v1/me", tags=["Auth"])


@router.get("", response_model=UserSummaryResponse, summary="현재 사용자 프로필")
async def get_me(
    current_user: UserSummaryResponse = Depends(get_current_user),
) -> UserSummaryResponse:
    return current_user


@router.get("/overview", response_model=UserOverviewResponse, summary="현재 사용자 자산 개요")
async def get_my_overview(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: UserOverviewService = Depends(get_user_overview_service),
) -> UserOverviewResponse:
    return await service.get_overview(user_id=current_user.id)


@router.get("/assets", response_model=UserAssetListResponse, summary="현재 사용자 소유 자산 목록")
async def get_my_assets(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: UserOverviewService = Depends(get_user_overview_service),
) -> UserAssetListResponse:
    return await service.list_assets(user_id=current_user.id)


@router.get("/groups", response_model=UserGroupListResponse, summary="현재 사용자 계산 그룹 목록")
async def get_my_groups(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: UserOverviewService = Depends(get_user_overview_service),
) -> UserGroupListResponse:
    return await service.list_groups(user_id=current_user.id)
