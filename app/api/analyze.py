"""
분석 엔드포인트.
"""
from fastapi import APIRouter, Depends
from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.application.di import get_analysis_service
from app.application.services.analysis_service import AnalysisService
import uuid

router = APIRouter()

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest, service: AnalysisService = Depends(get_analysis_service)):
    """
    새로운 분석 작업을 시작합니다.
    스텀 구현체.
    """
    return await service.analyze(request)
