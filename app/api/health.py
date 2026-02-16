"""
Health check endpoint.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.entities.analysis import HealthResponse
from app.gateway.db import get_db
# DISABLED: OpenSearch client import commented out to allow app startup
# from app.gateway.opensearch_client import get_opensearch_client
from app.config import settings

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    """
    Returns the service health status.
    Checks PostgreSQL and OpenSearch connectivity for informational purposes.
    Always returns HTTP 200 to prevent Kubernetes pod restarts on DB downtime.

    TEMPORARILY DISABLED: OpenSearch health check is disabled.
    """
    db_status = "ok"
    opensearch_status = "skipped"

    # Check PostgreSQL (informational only - does not affect HTTP status)
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    # DISABLED: OpenSearch health check temporarily disabled
    # Check OpenSearch (OPTIONAL - only if OPENSEARCH_HOST is configured)
    # if settings.OPENSEARCH_HOST:
    #     try:
    #         client = get_opensearch_client()
    #         if client is not None:
    #             ping_result = await client.ping()
    #             if not ping_result:
    #                 opensearch_status = "error"
    #             else:
    #                 opensearch_status = "ok"
    #             await client.close()
    #         else:
    #             opensearch_status = "skipped"
    #     except Exception:
    #         opensearch_status = "error"

    # Always return HTTP 200 - dependency status is informational only
    return {
        "status": "ok",
        "db": db_status,
        "opensearch": opensearch_status
    }
