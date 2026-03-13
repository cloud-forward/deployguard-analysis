"""
분석 작업 엔드포인트.
"""
from fastapi import APIRouter, Depends
from app.models.schemas import AnalysisJobRequest, AnalysisJobResponse
from app.application.di import get_analysis_service
from app.application.services.analysis_service import AnalysisService

router = APIRouter()


@router.post(
    "/analysis/jobs",
    response_model=AnalysisJobResponse,
    status_code=202,
    tags=["Analysis"],
    summary="분석 작업 수동 실행",
    description="""스캔 세션 ID를 지정하여 분석 작업을 수동으로 시작합니다.

일반적으로 분석은 `POST /api/v1/scans/{scan_id}/complete` 호출 시 자동으로 트리거됩니다.
이 엔드포인트는 재분석 또는 수동 오케스트레이션이 필요한 경우에 사용합니다.

분석 파이프라인: 그래프 구축 → 공격 경로 탐색 → 위험 점수 산정""",
    responses={
        202: {"description": "분석 작업이 성공적으로 접수되었습니다"},
        422: {"description": "유효하지 않은 요청 파라미터"},
    },
)
async def create_analysis_job(
    request: AnalysisJobRequest,
    service: AnalysisService = Depends(get_analysis_service),
):
    job_id = await service._jobs.create_analysis_job(
        cluster_id=request.cluster_id,
        k8s_scan_id=request.k8s_scan_id,
        aws_scan_id=request.aws_scan_id,
        image_scan_id=request.image_scan_id,
    )
    return AnalysisJobResponse(
        job_id=job_id,
        status="accepted",
        message=f"분석 작업이 시작되었습니다 (cluster_id={request.cluster_id})",
    )
