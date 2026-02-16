"""
Analysis endpoint.
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
    Trigger a new analysis job.
    Stub implementation.
    """
    # Delegate to application service
    return await service.analyze(request)
