"""
Main entry point for the FastAPI application.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import health, analyze, scan, clusters
from app.config import settings

app = FastAPI(
    title="DeployGuard 분석 엔진",
    description="""
DeployGuard는 인프라 그래프를 구축하고, 공격 경로를 탐색하며, 최적의 조치를 권장함으로써 Kubernetes 및 AWS 인프라 보안을 분석합니다.

## Scanner Orchestration Lifecycle

1. **Cluster registration**: `POST /api/v1/clusters`
2. **API token issuance**: scanner API token is managed in the cluster onboarding flow (not exposed by a dedicated public endpoint in this service)
3. **Scanner Helm installation**: scanner is installed with the issued token
4. **Scanner polling**: `GET /api/v1/scans/pending` with `Authorization: Bearer <api_token>`
5. **Scan execution + upload**: scanner uploads files via `POST /api/v1/scans/{scan_id}/upload-url`
6. **Completion notification**: scanner calls `POST /api/v1/scans/{scan_id}/complete`
7. **Analysis pipeline stage**: service transitions scan to `processing` and triggers only the implemented orchestration check (`maybe_trigger_analysis`)
""",
    version="4.0.0",
    openapi_tags=[
        {"name": "General"},
        {"name": "Analysis"},
        {
            "name": "Scans",
            "description": "스캔 데이터 수집/오케스트레이션 — queue 등록, scanner polling claim, upload, complete"
        },
        {
            "name": "Clusters",
            "description": "클러스터 관리 — 등록/조회/수정/삭제 및 scanner 인증 토큰 온보딩 컨텍스트"
        },
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://deployguard.org",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["General"])
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(scan.router)
app.include_router(clusters.router)

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
