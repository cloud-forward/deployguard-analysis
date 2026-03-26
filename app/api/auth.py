from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.application.di import get_auth_service, get_cluster_service
from app.application.services.auth_service import AuthService
from app.application.services.cluster_service import ClusterService
from app.config import settings
from app.models.schemas import ClusterResponse, UserSummaryResponse
from app.security.jwt import JWTError, decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)
user_bearer_scheme = HTTPBearer(auto_error=False)


def _extract_bearer_token(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme = credentials.scheme
    token = credentials.credentials
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Malformed Authorization header")
    return token.strip()


async def get_authenticated_cluster(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    cluster_service: ClusterService = Depends(get_cluster_service),
) -> ClusterResponse:
    token = _extract_bearer_token(credentials)
    cluster = await cluster_service.get_cluster_by_api_token(token)
    if cluster is None:
        raise HTTPException(status_code=403, detail="Invalid scanner API token")
    request.state.authenticated_cluster = cluster
    request.state.authenticated_cluster_id = cluster.id
    return cluster


async def get_request_user_id(x_user_id: str = Header(..., alias="X-User-Id")) -> str:
    user_id = x_user_id.strip()
    if not user_id:
        raise HTTPException(status_code=401, detail="Missing user identity")
    return user_id


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(user_bearer_scheme),
    auth_service: AuthService = Depends(get_auth_service),
) -> UserSummaryResponse:
    token = _extract_bearer_token(credentials)
    try:
        payload = decode_access_token(token, secret_key=settings.JWT_SECRET_KEY)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid access token") from exc

    user = await auth_service.get_user_by_id(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid access token")

    return UserSummaryResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
    )
