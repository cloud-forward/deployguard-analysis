"""
Health check endpoint.
"""
from fastapi import APIRouter
from app.domain.entities.analysis import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Returns the service health status.
    """
    return {"status": "healthy", "version": "0.1.0"}
