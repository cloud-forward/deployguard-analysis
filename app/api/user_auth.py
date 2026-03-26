from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status

from app.application.di import get_auth_service
from app.application.services.auth_service import AuthService, DuplicateEmailError
from app.config import settings
from app.models.schemas import LoginRequest, LoginResponse, SignupRequest, SignupResponse, UserSummaryResponse
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
            name=user.name,
            is_active=user.is_active,
        ),
    )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User signup",
)
async def signup(
    request: SignupRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        user = await auth_service.signup_user(request.email, request.password, name=request.name)
    except DuplicateEmailError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    return SignupResponse(
        user=UserSummaryResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            is_active=user.is_active,
        ),
    )
