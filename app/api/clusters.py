"""
Cluster management API endpoints.
"""
import logging
from typing import List
from fastapi import APIRouter, Depends, Response, status
from app.api.auth import get_request_user_id
from app.application.di import (
    get_attack_graph_service,
    get_cluster_service,
    get_recommendation_explanation_service,
)
from app.application.services.attack_graph_service import AttackGraphService
from app.application.services.cluster_service import ClusterService
from app.application.services.recommendation_explanation_service import RecommendationExplanationService
from app.models.schemas import (
    AttackPathDetailEnvelopeResponse,
    AttackPathListResponse,
    AttackGraphResponse,
    ClusterCreateRequest,
    ClusterUpdateRequest,
    ClusterResponse,
    ClusterCreateResponse,
    RecommendationExplanationRequest,
    RecommendationExplanationResponse,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationListResponse,
)

router = APIRouter(prefix="/api/v1/clusters", tags=["Clusters"])
logger = logging.getLogger(__name__)


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
- `self-managed` — 자체 관리 Kubernetes 클러스터
- `aws` — AWS 클러스터""",
    responses={
        201: {"description": "클러스터가 성공적으로 생성되었습니다"},
        422: {"description": "유효하지 않은 cluster_type 또는 필드 누락"},
    },
)
async def create_cluster(
    request: ClusterCreateRequest,
    user_id: str = Depends(get_request_user_id),
    service: ClusterService = Depends(get_cluster_service)
):
    return await service.create_cluster(request, user_id=user_id)


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


@router.get(
    "/{cluster_id}/attack-graph",
    response_model=AttackGraphResponse,
    summary="[신규] Attack Graph 조회",
    description=(
        "Attack Graph 화면의 그래프, 경로 목록, 상세 패널을 한 번에 구동하기 위한 MVP 응답입니다.\n\n"
        "초기 단계에서는 backend가 `label`, `severity`, boolean 기본값, 빈 `metadata`를 직접 정규화해서 반환합니다."
    ),
    responses={
        200: {"description": "클러스터 기준 최신 attack graph"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def get_attack_graph(
    cluster_id: str,
    service: AttackGraphService = Depends(get_attack_graph_service),
):
    return await service.get_attack_graph(cluster_id)


@router.get(
    "/{cluster_id}/attack-paths",
    response_model=AttackPathListResponse,
    summary="[신규] Persisted Attack Paths 조회",
    description="클러스터 기준 최신 분석에 연결된 persisted attack path 목록을 반환합니다.",
    responses={
        200: {"description": "클러스터 기준 최신 attack path 목록"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def get_attack_paths(
    cluster_id: str,
    service: AttackGraphService = Depends(get_attack_graph_service),
):
    return await service.get_attack_paths(cluster_id)


@router.get(
    "/{cluster_id}/attack-paths/{path_id}",
    response_model=AttackPathDetailEnvelopeResponse,
    summary="[신규] Persisted Attack Path 상세 조회",
    description="클러스터 기준 최신 분석에 연결된 특정 persisted attack path 상세를 반환합니다.",
    responses={
        200: {"description": "클러스터 기준 attack path 상세"},
        404: {"description": "클러스터 또는 attack path를 찾을 수 없습니다"},
    },
)
async def get_attack_path_detail(
    cluster_id: str,
    path_id: str,
    service: AttackGraphService = Depends(get_attack_graph_service),
):
    return await service.get_attack_path_detail(cluster_id, path_id)


@router.get(
    "/{cluster_id}/remediation-recommendations",
    response_model=RemediationRecommendationListResponse,
    summary="[신규] Persisted Remediation Recommendations 조회",
    description="클러스터 기준 최신 분석에 연결된 persisted remediation recommendation 목록을 반환합니다.",
    responses={
        200: {"description": "클러스터 기준 최신 remediation recommendation 목록"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def get_remediation_recommendations(
    cluster_id: str,
    service: AttackGraphService = Depends(get_attack_graph_service),
):
    logger.info(
        "remediation_list_request",
        extra={
            "route_name": "get_remediation_recommendations",
            "cluster_id": cluster_id,
            "request_status": "started",
        },
    )
    try:
        response = await service.get_remediation_recommendations(cluster_id)
    except Exception as exc:
        logger.exception(
            "remediation_list_request_failed",
            extra={
                "route_name": "get_remediation_recommendations",
                "cluster_id": cluster_id,
                "request_status": "failed",
                "exception_type": type(exc).__name__,
            },
        )
        raise
    logger.info(
        "remediation_list_request_completed",
        extra={
            "route_name": "get_remediation_recommendations",
            "cluster_id": cluster_id,
            "request_status": "succeeded",
            "recommendation_count": len(response.items),
        },
    )
    return response


@router.get(
    "/{cluster_id}/remediation-recommendations/{recommendation_id}",
    response_model=RemediationRecommendationDetailEnvelopeResponse,
    summary="[신규] Persisted Remediation Recommendation 상세 조회",
    description="클러스터 기준 최신 분석에 연결된 특정 persisted remediation recommendation 상세를 반환합니다.",
    responses={
        200: {"description": "클러스터 기준 remediation recommendation 상세"},
        404: {"description": "클러스터 또는 remediation recommendation을 찾을 수 없습니다"},
    },
)
async def get_remediation_recommendation_detail(
    cluster_id: str,
    recommendation_id: str,
    service: AttackGraphService = Depends(get_attack_graph_service),
):
    logger.info(
        "remediation_detail_request",
        extra={
            "route_name": "get_remediation_recommendation_detail",
            "cluster_id": cluster_id,
            "recommendation_id": recommendation_id,
            "request_status": "started",
        },
    )
    try:
        response = await service.get_remediation_recommendation_detail(cluster_id, recommendation_id)
    except Exception as exc:
        logger.exception(
            "remediation_detail_request_failed",
            extra={
                "route_name": "get_remediation_recommendation_detail",
                "cluster_id": cluster_id,
                "recommendation_id": recommendation_id,
                "request_status": "failed",
                "exception_type": type(exc).__name__,
            },
        )
        raise
    logger.info(
        "remediation_detail_request_completed",
        extra={
            "route_name": "get_remediation_recommendation_detail",
            "cluster_id": cluster_id,
            "recommendation_id": recommendation_id,
            "request_status": "succeeded",
            "recommendation_found": response.recommendation is not None,
        },
    )
    return response


@router.post(
    "/{cluster_id}/remediation-recommendations/{recommendation_id}/explanation",
    response_model=RecommendationExplanationResponse,
    summary="[신규] Remediation Recommendation 설명 생성",
    description="수동 요청으로 특정 remediation recommendation 상세에 대한 설명을 생성합니다.",
    responses={
        200: {"description": "설명 생성 결과"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
)
async def explain_remediation_recommendation(
    cluster_id: str,
    recommendation_id: str,
    request: RecommendationExplanationRequest,
    user_id: str = Depends(get_request_user_id),
    service: RecommendationExplanationService = Depends(get_recommendation_explanation_service),
):
    logger.info(
        "remediation_explanation_request",
        extra={
            "route_name": "explain_remediation_recommendation",
            "cluster_id": cluster_id,
            "recommendation_id": recommendation_id,
            "requested_provider": request.provider.value if request.provider is not None else None,
            "requested_model": request.model,
            "request_status": "started",
        },
    )
    try:
        response = await service.explain_recommendation(
            cluster_id=cluster_id,
            recommendation_id=recommendation_id,
            user_id=user_id,
            request=request,
        )
    except Exception as exc:
        logger.exception(
            "remediation_explanation_request_failed",
            extra={
                "route_name": "explain_remediation_recommendation",
                "cluster_id": cluster_id,
                "recommendation_id": recommendation_id,
                "request_status": "failed",
                "exception_type": type(exc).__name__,
            },
        )
        raise
    logger.info(
        "remediation_explanation_request_completed",
        extra={
            "route_name": "explain_remediation_recommendation",
            "cluster_id": cluster_id,
            "recommendation_id": recommendation_id,
            "request_status": "succeeded",
            "explanation_status": response.explanation_status,
            "used_llm": response.used_llm,
            "provider": response.provider,
            "model": response.model,
            "fallback_reason": response.fallback_reason,
        },
    )
    return response


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
