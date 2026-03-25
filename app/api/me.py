from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.application.di import get_user_overview_service
from app.application.services.user_overview_service import UserOverviewService
from app.models.schemas import UserOverviewResponse, UserSummaryResponse


router = APIRouter(prefix="/api/v1/me", tags=["Auth"])


@router.get("/overview", response_model=UserOverviewResponse, summary="현재 사용자 자산 개요")
async def get_my_overview(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: UserOverviewService = Depends(get_user_overview_service),
) -> UserOverviewResponse:
    return await service.get_overview(user_id=current_user.id)
