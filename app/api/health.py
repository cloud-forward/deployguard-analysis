"""
Health check endpoint.
"""
from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.entities.analysis import HealthResponse
from app.gateway.db import get_db
from app.gateway.opensearch_client import get_opensearch_client
from app.config import settings

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Returns the service health status.
    Checks PostgreSQL (mandatory) and OpenSearch (optional) connectivity.
    Returns 503 if DB check fails or if OpenSearch is configured but unavailable.
    """
    db_status = "ok"
    opensearch_status = "skipped"

    # Check PostgreSQL (MANDATORY)
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    # Check OpenSearch (OPTIONAL - only if OPENSEARCH_HOST is configured)
    if settings.OPENSEARCH_HOST:
        try:
            client = get_opensearch_client()
            ping_result = await client.ping()
            if not ping_result:
                opensearch_status = "error"
            else:
                opensearch_status = "ok"
            await client.close()
        except Exception:
            opensearch_status = "error"

    # Set 503 status if DB is down or if OpenSearch is configured but down
    if db_status == "error" or opensearch_status == "error":
        response.status_code = 503
        return {
            "status": "error",
            "db": db_status,
            "opensearch": opensearch_status
        }

    return {
        "status": "ok",
        "db": db_status,
        "opensearch": opensearch_status
    }
