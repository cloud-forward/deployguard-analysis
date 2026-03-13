"""
분석 엔드포인트.
"""
from fastapi import APIRouter, Depends
from app.models.schemas import AnalysisRequest, AnalysisResponse
from app.application.di import get_analysis_service
from app.application.services.analysis_service import AnalysisService

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    tags=["Analysis"],
    summary="분석 작업 시작",
    description="""새로운 분석 작업을 시작합니다.

대상 리소스에 대해 그래프 구축 → 공격 경로 탐색 → 위험 점수 산정 파이프라인을 실행합니다.
분석은 비동기로 실행되며, 반환된 `job_id`로 진행 상황을 추적할 수 있습니다.

**depth 값:**
- 최솟값: `1` (얕은 분석)
- 기본값: `3`
- 최댓값: `10` (전체 경로 탐색)""",
    responses={
        200: {"description": "분석 작업이 성공적으로 시작되었습니다"},
        422: {"description": "유효하지 않은 요청 파라미터"},
    },
)
async def analyze(request: AnalysisRequest, service: AnalysisService = Depends(get_analysis_service)):
    return await service.analyze(request)
