from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.application.di import get_inventory_service
from app.application.services.inventory_service import InventoryService
from app.models.schemas import SyncResponse, UserSummaryResponse

router = APIRouter(prefix="/api/v1/clusters", tags=["Inventory"])


@router.post(
    "/{cluster_id}/sync",
    response_model=SyncResponse,
    status_code=200,
    summary="클러스터 Discovery Inventory 동기화",
    description="지정한 클러스터의 AWS Discovery Inventory 수집을 실행하고 최신 스냅샷을 저장합니다.",
    responses={
        200: {"description": "동기화가 성공적으로 완료되었습니다"},
        400: {"description": "클러스터에 AWS discovery 설정이 없습니다"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def sync_cluster(
    cluster_id: str,
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: InventoryService = Depends(get_inventory_service),
) -> SyncResponse:
    return await service.sync_cluster(cluster_id, user_id=current_user.id)
