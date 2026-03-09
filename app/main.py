"""
Main entry point for the FastAPI application.
"""
from fastapi import FastAPI
from app.api import health, analyze, scan
from app.config import settings

app = FastAPI(
    title="DeployGuard 분석 엔진",
    description="""
DeployGuard는 인프라 그래프를 구축하고, 공격 경로를 탐색하며, 최적의 조치를 권장함으로써 Kubernetes 및 AWS 인프라 보안을 분석합니다.

## 스캔 데이터 수집 흐름

1. **스캔 세션 시작**: `POST /api/scans/start` → `scan_id` 수신
2. **업로드 URL 요청**: `POST /api/scans/{scan_id}/upload-url` → S3 presigned URL 수신
3. **파일 업로드**: presigned URL로 파일을 직접 `PUT` (클라이언트 → S3)
4. **스캔 완료 알림**: `POST /api/scans/{scan_id}/complete` → 분석 파이프라인 트리거
""",
    version="4.0.0",
    openapi_tags=[
        {"name": "General"},
        {"name": "Analysis"},
        {
            "name": "Scans",
            "description": "스캔 데이터 수집 — 스캔 세션 시작, 업로드 URL 요청, 완료 알림"
        },
    ]
)

app.include_router(health.router, tags=["General"])
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(scan.router)

@app.get("/")
async def root():
    """기본 서비스 정보를 반환하는 루트 엔드포인트."""
    return {
        "service": settings.PROJECT_NAME,
        "docs": "/docs",
        "health": "/health"
    }

from app.gateway.db.base import Base
from app.gateway.db.session import engine
from app.models import db_models as _db_models  # noqa: F401 — ensures ScanRecord is registered with Base.metadata

@app.on_event("startup")
async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
