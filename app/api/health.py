"""
서비스 상태 확인 엔드포인트.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.entities.analysis import HealthResponse
from app.gateway.db.session import get_db

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    """
    서비스 상태를 반환합니다.
    정보 제공 목적으로 PostgreSQL 연결을 확인합니다.
    DB 장애 시 Kubernetes 파드 재시작을 방지하기 위해 항상 HTTP 200을 반환합니다.
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
