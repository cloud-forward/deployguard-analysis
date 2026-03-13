"""
Cluster management API endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, Response, status
from app.application.di import get_cluster_service
from app.application.services.cluster_service import ClusterService
from app.models.schemas import ClusterCreateRequest, ClusterUpdateRequest, ClusterResponse

router = APIRouter(prefix="/api/clusters", tags=["Clusters"])


@router.post(
    "",
    response_model=ClusterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new cluster",
)
async def create_cluster(
    request: ClusterCreateRequest,
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.create_cluster(request)


@router.get(
    "",
    response_model=List[ClusterResponse],
    summary="List all clusters",
)
async def list_clusters(
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.list_clusters()


@router.get(
    "/{id}",
    response_model=ClusterResponse,
    summary="Get a cluster by ID",
)
async def get_cluster(
    id: str,
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.get_cluster(id)


@router.patch(
    "/{id}",
    response_model=ClusterResponse,
    summary="Update a cluster",
)
async def update_cluster(
    id: str,
    request: ClusterUpdateRequest,
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.update_cluster(id, request)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a cluster",
)
async def delete_cluster(
    id: str,
    service: ClusterService = Depends(get_cluster_service)
):
    await service.delete_cluster(id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
