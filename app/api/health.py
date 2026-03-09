"""
Health check endpoint.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.entities.analysis import HealthResponse
from app.gateway.db import get_db

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    """
    Returns the service health status.
    Checks PostgreSQL connectivity for informational purposes.
    Always returns HTTP 200 to prevent Kubernetes pod restarts on DB downtime.
    """
    db_status = "ok"

    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    return {
        "status": "ok",
        "db": db_status,
    }
