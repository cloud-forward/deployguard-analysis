from fastapi import APIRouter, Depends

from app.application.di import get_inventory_service
from app.application.services.inventory_service import InventoryService
from app.models.schemas import AssetDetailResponse, AssetInventoryListResponse

router = APIRouter(tags=["Clusters"])


@router.get(
    "/api/v1/clusters/{cluster_id}/assets",
    response_model=AssetInventoryListResponse,
    status_code=200,
    summary="클러스터 Discovery Inventory 조회",
    description="지정한 클러스터의 최신 Discovery Inventory 스냅샷을 읽어 자산 목록을 반환합니다.",
    responses={
        200: {"description": "클러스터 자산 목록"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def get_cluster_assets(
    cluster_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> AssetInventoryListResponse:
    return await service.get_cluster_assets(cluster_id)


@router.get(
    "/api/v1/assets/{asset_id:path}",
    response_model=AssetDetailResponse,
    status_code=200,
    summary="Discovery Inventory 자산 상세 조회",
    description="최신 Discovery Inventory 스냅샷들에서 자산을 찾아 상세 정보를 반환합니다.",
    responses={
        200: {"description": "자산 상세 정보"},
        404: {"description": "자산을 찾을 수 없습니다"},
    },
)
async def get_asset_detail(
    asset_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> AssetDetailResponse:
    return await service.get_asset_detail(asset_id)
