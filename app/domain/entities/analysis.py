"""
Pydantic domain entities and DTOs for analysis use-cases.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class AnalysisRequest(BaseModel):
    """Request model for the /analyze endpoint."""
    target_id: str = Field(..., description="ID of the target to analyze")
    depth: int = Field(default=3, ge=1, le=10)
    parameters: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    """Response model for the /analyze endpoint."""
    job_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """Response model for the /health endpoint."""
    status: str
    db: Optional[str] = None
    opensearch: Optional[str] = None
