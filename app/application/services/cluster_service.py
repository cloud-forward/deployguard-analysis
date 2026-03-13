"""
Application service for Cluster management.
"""
from __future__ import annotations
from typing import List, Optional
from fastapi import HTTPException
from app.domain.repositories.cluster_repository import ClusterRepository
from app.models.schemas import ClusterCreateRequest, ClusterUpdateRequest, ClusterResponse


class ClusterService:
    def __init__(self, cluster_repository: ClusterRepository):
        self._repo = cluster_repository

    async def create_cluster(self, request: ClusterCreateRequest) -> ClusterResponse:
        existing = await self._repo.get_by_name(request.name)
        if existing:
            raise HTTPException(status_code=400, detail=f"Cluster with name '{request.name}' already exists")
        
        cluster = await self._repo.create(
            name=request.name,
            cluster_type=request.cluster_type,
            description=request.description
        )
        return ClusterResponse.model_validate(cluster)

    async def get_cluster(self, cluster_id: str) -> ClusterResponse:
        cluster = await self._repo.get_by_id(cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail=f"Cluster with ID '{cluster_id}' not found")
        return ClusterResponse.model_validate(cluster)

    async def list_clusters(self) -> List[ClusterResponse]:
        clusters = await self._repo.list_all()
        return [ClusterResponse.model_validate(c) for c in clusters]

    async def update_cluster(self, cluster_id: str, request: ClusterUpdateRequest) -> ClusterResponse:
        update_data = request.model_dump(exclude_unset=True)
        if not update_data:
             cluster = await self._repo.get_by_id(cluster_id)
             if not cluster:
                 raise HTTPException(status_code=404, detail=f"Cluster with ID '{cluster_id}' not found")
             return ClusterResponse.model_validate(cluster)

        if "name" in update_data:
            existing = await self._repo.get_by_name(update_data["name"])
            if existing and getattr(existing, "id") != cluster_id:
                raise HTTPException(status_code=400, detail=f"Cluster with name '{update_data['name']}' already exists")

        cluster = await self._repo.update(cluster_id, **update_data)
        if not cluster:
            raise HTTPException(status_code=404, detail=f"Cluster with ID '{cluster_id}' not found")
        return ClusterResponse.model_validate(cluster)

    async def delete_cluster(self, cluster_id: str) -> None:
        success = await self._repo.delete(cluster_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Cluster with ID '{cluster_id}' not found")
