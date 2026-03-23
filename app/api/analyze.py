"""
분석 작업 엔드포인트.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from app.models.schemas import (
    AnalysisJobDetailResponse,
    AnalysisJobRequest,
    AnalysisJobResponse,
    ClusterAnalysisJobListResponse,
    DebugAnalysisExecuteRequest,
)
from app.application.di import get_analysis_service
from app.application.services.analysis_service import AnalysisService

router = APIRouter()


@router.post(
    "/analysis/jobs",
    response_model=AnalysisJobResponse,
    status_code=202,
    tags=["Analysis"],
    summary="표준 분석 작업 생성",
    description="""표준 persisted-job 워크플로우의 1단계입니다.

프론트엔드/제품 흐름은 이 엔드포인트로 `analysis_jobs` row를 생성한 뒤,
`POST /api/v1/analysis/jobs/{job_id}/execute`를 호출해 실제 분석을 실행합니다.

요청에 포함된 scan_id만 검증 후 job에 고정되며, 이후 실행은 cluster 단위 최신 스캔 추론 없이
analysis_jobs에 저장된 명시적 scan IDs를 기준으로 진행됩니다.""",
    responses={
        202: {"description": "분석 작업이 성공적으로 접수되었습니다"},
        422: {"description": "유효하지 않은 요청 파라미터"},
    },
)
async def create_analysis_job(
    request: AnalysisJobRequest,
    service: AnalysisService = Depends(get_analysis_service),
):
    return await service.create_analysis_job(
        k8s_scan_id=request.k8s_scan_id,
        aws_scan_id=request.aws_scan_id,
        image_scan_id=request.image_scan_id,
    )


@router.get(
    "/clusters/{cluster_id}/analysis/jobs",
    response_model=ClusterAnalysisJobListResponse,
    status_code=200,
    tags=["Analysis"],
    summary="클러스터 분석 작업 목록 조회",
    description="""수동 분석 워크플로우용 persisted analysis job 목록을 클러스터 기준으로 조회합니다.

선택한 scan_id와 현재 실행 상태를 프론트엔드에서 폴링/이력 표시할 수 있도록 반환합니다.""",
)
async def list_analysis_jobs(
    cluster_id: str,
    status: str | None = Query(default=None),
    service: AnalysisService = Depends(get_analysis_service),
):
    return await service.list_analysis_jobs(cluster_id=cluster_id, status=status)


@router.get(
    "/analysis/jobs/{job_id}",
    response_model=AnalysisJobDetailResponse,
    status_code=200,
    tags=["Analysis"],
    summary="분석 작업 단건 조회",
    description="""persisted analysis job 1건의 선택된 scan_id와 실행 상태를 조회합니다.""",
    responses={
        200: {"description": "분석 작업 상세"},
        404: {"description": "분석 작업을 찾을 수 없습니다"},
    },
)
async def get_analysis_job(
    job_id: str,
    service: AnalysisService = Depends(get_analysis_service),
):
    return await service.get_analysis_job(job_id)


# ✨ 새로운 엔드포인트 1: 분석 결과 조회
@router.get(
    "/analysis/{job_id}/result",
    tags=["Analysis"],
    summary="분석 결과 조회",
)
async def get_analysis_result(
    job_id: str,
    service: AnalysisService = Depends(get_analysis_service),
):
    """
    Get analysis result by job ID.
    
    Returns attack paths and risk scores.
    """
    # TODO: Implement job result retrieval from database
    return {
        "job_id": job_id,
        "status": "completed",
        "message": "Analysis result retrieval not yet implemented",
    }


# ✨ 새로운 엔드포인트 2: 즉시 실행 (테스트용)
@router.post(
    "/analysis/jobs/{job_id}/execute",
    tags=["Analysis"],
    summary="표준 분석 작업 실행",
    description="""표준 persisted-job 워크플로우의 2단계입니다.

이미 생성된 `analysis_jobs` row를 읽고, 그 row에 저장된 `k8s_scan_id`, `aws_scan_id`, `image_scan_id`
기준으로 raw scan 데이터를 로드해 분석을 실행합니다.""",
)
async def execute_analysis_job(
    job_id: str,
    service: AnalysisService = Depends(get_analysis_service),
):
    try:
        return await service.execute_analysis_job(job_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis execution failed: {str(e)}"
        )


@router.post(
    "/analysis/execute",
    tags=["Analysis"],
    summary="분석 즉시 실행 (내부 디버그/검증 전용)",
    description="""내부 디버그/검증 전용 엔드포인트입니다.

이 경로는 persisted `analysis_jobs` 생성 없이 분석을 즉시 실행하므로 표준 프론트엔드/제품 흐름이 아닙니다.
표준 제품 흐름은 `POST /api/v1/analysis/jobs` 후 `POST /api/v1/analysis/jobs/{job_id}/execute`를 사용해야 합니다.""",
)
async def execute_analysis_endpoint(
    request: DebugAnalysisExecuteRequest,
    service: AnalysisService = Depends(get_analysis_service),
):
    """
    Execute analysis directly (for testing).
    
    This endpoint bypasses the job queue and executes analysis immediately.
    """
    try:
        result = await service.execute_analysis_debug(
            k8s_scan_id=request.k8s_scan_id,
            aws_scan_id=request.aws_scan_id,
            image_scan_id=request.image_scan_id,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis execution failed: {str(e)}"
        )
