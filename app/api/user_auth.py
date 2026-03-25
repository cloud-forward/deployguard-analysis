from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status

from app.application.di import get_auth_service
from app.application.services.auth_service import AuthService
from app.config import settings
from app.models.schemas import LoginRequest, LoginResponse, UserSummaryResponse
from app.security.jwt import create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
)
async def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    user = await auth_service.authenticate_user(request.email, request.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    access_token = create_access_token(
        user.id,
        secret_key=settings.JWT_SECRET_KEY,
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserSummaryResponse(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
        ),
    )
