from fastapi import APIRouter, Depends

from app.application.di import get_inventory_service
from app.application.services.inventory_service import InventoryService
from app.models.schemas import AssetDetailResponse, AssetInventoryListResponse

router = APIRouter(prefix="/api/v1", tags=["Discovery Inventory"])


@router.get("/clusters/{cluster_id}/assets", response_model=AssetInventoryListResponse)
async def get_assets(
    cluster_id: str,
    service: InventoryService = Depends(get_inventory_service),
):
    return await service.get_cluster_assets(cluster_id)


@router.get("/assets/{asset_id}", response_model=AssetDetailResponse)
async def get_asset_detail(
    asset_id: str,
    service: InventoryService = Depends(get_inventory_service),
):
    return await service.get_asset_detail(asset_id)
