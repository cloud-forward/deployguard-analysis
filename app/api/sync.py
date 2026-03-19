from fastapi import APIRouter, Depends

from app.application.di import get_inventory_service
from app.application.services.inventory_service import InventoryService
from app.models.schemas import SyncResponse

router = APIRouter(prefix="/api/v1", tags=["Discovery Inventory"])


@router.post("/clusters/{cluster_id}/sync", response_model=SyncResponse)
async def sync_cluster(
    cluster_id: str,
    service: InventoryService = Depends(get_inventory_service),
):
    return await service.sync_cluster(cluster_id)
