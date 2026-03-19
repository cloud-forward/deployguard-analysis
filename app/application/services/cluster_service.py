"""
Application service for Cluster management.
"""
from __future__ import annotations
import secrets
from typing import List, Optional
from fastapi import HTTPException
from app.domain.repositories.cluster_repository import ClusterRepository
from app.models.schemas import (
    ClusterCreateRequest,
    ClusterUpdateRequest,
    ClusterResponse,
    ClusterCreateResponse,
    ClusterOnboardingResponse,
)


class ClusterService:
    def __init__(self, cluster_repository: ClusterRepository):
        self._repo = cluster_repository

    def _build_onboarding(self, cluster_id: str, cluster_type: str, api_token: str) -> ClusterOnboardingResponse:
        if cluster_type == "aws":
            return ClusterOnboardingResponse(
                installation_method="docker-compose",
                install_command="docker compose up -d",
                required_values={
                    "clusterId": cluster_id,
                    "apiToken": api_token,
                },
                required_environment_variables=[
                    "DEPLOYGUARD_CLUSTER_ID",
                    "DEPLOYGUARD_API_TOKEN",
                    "AWS_REGION",
                    "AWS_ROLE_ARN",
                ],
                guidance=[
                    "Set the required environment variables in your docker-compose environment section.",
                    "Prepare an IAM role with the AWS permissions needed for scanning and set its ARN as AWS_ROLE_ARN.",
                ],
            )

        return ClusterOnboardingResponse(
            installation_method="helm",
            install_command="helm upgrade --install deployguard-scanner deployguard/scanner",
            required_values={
                "clusterId": cluster_id,
                "apiToken": api_token,
                "imagePullSecret": "deployguard-registry",
            },
            guidance=[
                "Set clusterId and apiToken in the Helm values.",
                "Configure imagePullSecret so the scanner image can be pulled.",
            ],
        )

    async def create_cluster(self, request: ClusterCreateRequest) -> ClusterCreateResponse:
        existing = await self._repo.get_by_name(request.name)
        if existing:
            raise HTTPException(status_code=400, detail=f"Cluster with name '{request.name}' already exists")

        api_token = f"dg_scanner_{secrets.token_urlsafe(24)}"
        cluster = await self._repo.create(
            name=request.name,
            cluster_type=request.cluster_type,
            description=request.description,
            api_token=api_token,
            aws_account_id=request.aws_account_id,
            aws_role_arn=request.aws_role_arn,
            aws_region=request.aws_region,
        )
        return ClusterCreateResponse.model_validate({
            **cluster.__dict__,
            "onboarding": self._build_onboarding(cluster.id, cluster.cluster_type, api_token),
        })

    async def get_cluster(self, cluster_id: str) -> ClusterResponse:
        cluster = await self._repo.get_by_id(cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail=f"Cluster with ID '{cluster_id}' not found")
        return ClusterResponse.model_validate(cluster)

    async def get_cluster_by_api_token(self, api_token: str) -> Optional[ClusterResponse]:
        cluster = await self._repo.get_by_api_token(api_token)
        if not cluster:
            return None
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
