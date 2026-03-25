from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.application.di import get_cluster_service
from app.application.services.cluster_service import ClusterService
from app.models.schemas import ClusterResponse


bearer_scheme = HTTPBearer(auto_error=False)


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
