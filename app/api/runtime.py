"""
Runtime snapshot direct upload API endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import get_authenticated_cluster, get_current_user
from app.application.di import get_runtime_snapshot_service
from app.application.services.runtime_snapshot_service import RuntimeSnapshotService
from app.models.schemas import (
    RuntimeActivityListResponse,
    ClusterResponse,
    RuntimeCompleteRequest,
    RuntimeCompleteResponse,
    RuntimeStatusResponse,
    RuntimeUploadUrlResponse,
    UserSummaryResponse,
)


router = APIRouter(prefix="/api/v1", tags=["Runtime"])


@router.post(
    "/runtime/upload-url",
    response_model=RuntimeUploadUrlResponse,
    status_code=status.HTTP_200_OK,
)
async def create_runtime_upload_url(
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_upload_url(authenticated_cluster_id=authenticated_cluster.id)


@router.post(
    "/runtime/complete",
    response_model=RuntimeCompleteResponse,
    status_code=status.HTTP_200_OK,
)
async def complete_runtime_upload(
    request: RuntimeCompleteRequest,
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.complete_upload(
        authenticated_cluster_id=authenticated_cluster.id,
        s3_key=request.s3_key,
        snapshot_at=request.snapshot_at,
        fact_count=request.fact_count,
    )


@router.get(
    "/clusters/{cluster_id}/runtime/status",
    response_model=RuntimeStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def get_runtime_status(
    cluster_id: str,
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_status(cluster_id=cluster_id, user_id=current_user.id)


@router.get(
    "/clusters/{cluster_id}/runtime/activities",
    response_model=RuntimeActivityListResponse,
    status_code=status.HTTP_200_OK,
)
async def get_runtime_activities(
    cluster_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    snapshot_limit: int = Query(default=1, ge=1, le=20),
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_activities(
        cluster_id=cluster_id,
        user_id=current_user.id,
        limit=limit,
        snapshot_limit=snapshot_limit,
    )
