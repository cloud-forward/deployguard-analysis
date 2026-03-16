"""
Cluster management API endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, Response, status
from app.application.di import get_cluster_service
from app.application.services.cluster_service import ClusterService
from app.models.schemas import ClusterCreateRequest, ClusterUpdateRequest, ClusterResponse, ClusterCreateResponse

router = APIRouter(prefix="/api/v1/clusters", tags=["Clusters"])


@router.post(
    "",
    response_model=ClusterCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="클러스터 생성",
    description="""DeployGuard 분석 대상 Kubernetes 클러스터를 등록합니다.
클러스터 등록 시 스캐너 인증용 API 토큰이 함께 발급되며 응답 본문으로 1회 반환됩니다.
발급된 토큰은 스캐너 Helm 설치 시 설정값으로 사용해야 하며, 이후 일반 조회 API에서는 노출되지 않습니다.

**cluster_type 값:**
- `eks` — AWS EKS 관리형 클러스터
- `self-managed` — 자체 관리 Kubernetes 클러스터""",
    responses={
        201: {"description": "클러스터가 성공적으로 생성되었습니다"},
        422: {"description": "유효하지 않은 cluster_type 또는 필드 누락"},
    },
)
async def create_cluster(
    request: ClusterCreateRequest,
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.create_cluster(request)


@router.get(
    "",
    response_model=List[ClusterResponse],
    summary="클러스터 목록 조회",
    description="등록된 모든 클러스터 목록을 반환합니다.",
    responses={
        200: {"description": "클러스터 목록"},
    },
)
async def list_clusters(
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.list_clusters()


@router.get(
    "/{id}",
    response_model=ClusterResponse,
    summary="클러스터 단건 조회",
    description="ID로 특정 클러스터의 상세 정보를 조회합니다.",
    responses={
        200: {"description": "클러스터 정보"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def get_cluster(
    id: str,
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.get_cluster(id)


@router.patch(
    "/{id}",
    response_model=ClusterResponse,
    summary="클러스터 정보 수정",
    description="클러스터의 이름, 설명, 유형을 부분 업데이트합니다. 변경할 필드만 포함하면 됩니다.",
    responses={
        200: {"description": "수정된 클러스터 정보"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
        422: {"description": "유효하지 않은 cluster_type"},
    },
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
    summary="클러스터 삭제",
    description="클러스터와 연결된 모든 스캔 데이터를 포함하여 클러스터를 삭제합니다.",
    responses={
        204: {"description": "클러스터가 성공적으로 삭제되었습니다"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def delete_cluster(
    id: str,
    service: ClusterService = Depends(get_cluster_service)
):
    await service.delete_cluster(id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
