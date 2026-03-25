"""
Application service for Discovery Inventory.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from fastapi import HTTPException

from app.application.services.aws_auth import assume_role
from app.application.services.aws_collectors import collect_all_assets
from app.models.schemas import (
    AssetDetailResponse,
    AssetInventoryItemResponse,
    AssetInventoryListResponse,
    AssetStatusResponse,
    ClusterCreateRequest,
    ClusterListResponse,
    ClusterResponse,
    InventorySummaryResponse,
    SyncResponse,
)


class InventoryService:
    def __init__(self, cluster_repository, inventory_snapshot_repository):
        self._clusters = cluster_repository
        self._snapshots = inventory_snapshot_repository

    async def create_cluster(self, request: ClusterCreateRequest) -> ClusterResponse:
        cluster = await self._clusters.create(
            name=request.name,
            cluster_type="aws",
            aws_account_id=request.aws_account_id,
            aws_role_arn=request.aws_role_arn,
            aws_region=request.aws_region,
        )
        return _cluster_to_response(cluster)

    async def list_clusters(self, user_id: str) -> ClusterListResponse:
        clusters = await self._clusters.list_all(user_id)
        return ClusterListResponse(clusters=[_cluster_to_response(cluster) for cluster in clusters])

    async def sync_cluster(self, cluster_id: str, user_id: str | None = None) -> SyncResponse:
        cluster = await self._get_cluster_or_404(cluster_id, user_id=user_id)
        if not cluster.aws_account_id or not cluster.aws_role_arn or not cluster.aws_region:
            raise HTTPException(status_code=400, detail="Cluster is missing AWS discovery configuration")

        session = await asyncio.to_thread(assume_role, cluster.aws_role_arn)
        result = await asyncio.to_thread(
            collect_all_assets,
            session,
            cluster.aws_account_id,
            cluster.aws_region,
        )
        scanned_at = _parse_scanned_at(result["scanned_at"])
        await self._snapshots.create(
            cluster_id=cluster_id,
            scan_id=result["scan_id"],
            scanned_at=scanned_at,
            raw_result_json=result,
        )
        return SyncResponse(status="success", cluster_id=cluster_id, scan_id=result["scan_id"])

    async def get_cluster_assets(self, cluster_id: str, user_id: str | None = None) -> AssetInventoryListResponse:
        cluster = await self._get_cluster_or_404(cluster_id, user_id=user_id)
        snapshot = await self._snapshots.get_latest_by_cluster(cluster_id)
        if snapshot is None:
            return AssetInventoryListResponse(summary=InventorySummaryResponse(total_assets=0), assets=[])
        return build_inventory_list_response(_cluster_to_response(cluster), snapshot.raw_result_json)

    async def get_asset_detail(self, asset_id: str, user_id: str | None = None) -> AssetDetailResponse:
        snapshots = await self._snapshots.list_latest()
        for snapshot in snapshots:
            cluster = await self._clusters.get_by_id(snapshot.cluster_id, user_id=user_id)
            if cluster is None:
                continue
            inventory = build_inventory_list_response(_cluster_to_response(cluster), snapshot.raw_result_json)
            for asset in inventory.assets:
                if asset.asset_id == asset_id:
                    return AssetDetailResponse(**asset.model_dump())
        raise HTTPException(status_code=404, detail="Asset not found")

    async def _get_cluster_or_404(self, cluster_id: str, user_id: str | None = None):
        cluster = await self._clusters.get_by_id(cluster_id, user_id=user_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        return cluster


def build_ec2_item(cluster: ClusterResponse, ec2: dict[str, Any]) -> AssetInventoryItemResponse:
    return AssetInventoryItemResponse(
        asset_id=f"ec2:{ec2['instance_id']}",
        asset_type="ec2",
        name=ec2["instance_id"],
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        account_id=cluster.aws_account_id or "",
        region=cluster.aws_region,
        status=AssetStatusResponse(),
        details={
            "private_ip": ec2.get("private_ip"),
            "iam_instance_profile": ec2.get("iam_instance_profile"),
            "metadata_options": ec2.get("metadata_options", {}),
            "security_groups": ec2.get("security_groups", []),
        },
    )


def build_s3_item(cluster: ClusterResponse, bucket: dict[str, Any]) -> AssetInventoryItemResponse:
    return AssetInventoryItemResponse(
        asset_id=f"s3:{bucket['name']}",
        asset_type="s3",
        name=bucket["name"],
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        account_id=cluster.aws_account_id or "",
        region=None,
        status=AssetStatusResponse(),
        details={
            "arn": bucket.get("arn"),
            "public_access_block": bucket.get("public_access_block"),
            "encryption": bucket.get("encryption"),
            "versioning": bucket.get("versioning"),
            "logging_enabled": bucket.get("logging_enabled"),
        },
    )


def build_rds_item(cluster: ClusterResponse, rds: dict[str, Any]) -> AssetInventoryItemResponse:
    return AssetInventoryItemResponse(
        asset_id=f"rds:{rds['identifier']}",
        asset_type="rds",
        name=rds["identifier"],
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        account_id=cluster.aws_account_id or "",
        region=cluster.aws_region,
        status=AssetStatusResponse(),
        details={
            "arn": rds.get("arn"),
            "engine": rds.get("engine"),
            "engine_version": rds.get("engine_version"),
            "storage_encrypted": rds.get("storage_encrypted"),
            "publicly_accessible": rds.get("publicly_accessible"),
            "vpc_security_groups": rds.get("vpc_security_groups", []),
        },
    )


def build_iam_role_item(cluster: ClusterResponse, role: dict[str, Any]) -> AssetInventoryItemResponse:
    return AssetInventoryItemResponse(
        asset_id=f"iam-role:{role['name']}",
        asset_type="iam_role",
        name=role["name"],
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        account_id=cluster.aws_account_id or "",
        region=None,
        status=AssetStatusResponse(),
        details={
            "arn": role.get("arn"),
            "is_irsa": role.get("is_irsa"),
            "irsa_oidc_issuer": role.get("irsa_oidc_issuer"),
            "trust_policy": role.get("trust_policy", {}),
            "attached_policies": role.get("attached_policies", []),
            "inline_policies": role.get("inline_policies", []),
        },
    )


def build_iam_user_item(cluster: ClusterResponse, user: dict[str, Any]) -> AssetInventoryItemResponse:
    return AssetInventoryItemResponse(
        asset_id=f"iam-user:{user['username']}",
        asset_type="iam_user",
        name=user["username"],
        cluster_id=cluster.id,
        cluster_name=cluster.name,
        account_id=cluster.aws_account_id or "",
        region=None,
        status=AssetStatusResponse(),
        details={
            "arn": user.get("arn"),
            "access_keys": user.get("access_keys", []),
            "attached_policies": user.get("attached_policies", []),
            "inline_policies": user.get("inline_policies", []),
            "has_mfa": user.get("has_mfa"),
            "last_used": user.get("last_used"),
        },
    )


def build_inventory_list_response(
    cluster: ClusterResponse,
    scan: dict[str, Any],
) -> AssetInventoryListResponse:
    items = [
        *(build_iam_role_item(cluster, item) for item in scan.get("iam_roles", [])),
        *(build_iam_user_item(cluster, item) for item in scan.get("iam_users", [])),
        *(build_s3_item(cluster, item) for item in scan.get("s3_buckets", [])),
        *(build_rds_item(cluster, item) for item in scan.get("rds_instances", [])),
        *(build_ec2_item(cluster, item) for item in scan.get("ec2_instances", [])),
    ]
    return AssetInventoryListResponse(
        summary=InventorySummaryResponse(total_assets=len(items)),
        assets=items,
    )


def _cluster_to_response(cluster: Any) -> ClusterResponse:
    return ClusterResponse(
        id=str(cluster.id),
        name=cluster.name,
        description=getattr(cluster, "description", None),
        cluster_type=getattr(cluster, "cluster_type", None),
        aws_account_id=getattr(cluster, "aws_account_id", None),
        aws_role_arn=getattr(cluster, "aws_role_arn", None),
        aws_region=getattr(cluster, "aws_region", None),
    )


def _parse_scanned_at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
