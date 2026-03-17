"""
Main entry point for the FastAPI application.
"""
import logging
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.api import health, analyze, scan, clusters
from app.config import settings

logger = logging.getLogger("deployguard.request")
_SKIP_LOG_PATHS = {"/docs", "/redoc", "/openapi.json"}

app = FastAPI(
    title="DeployGuard 분석 엔진",
    description="""
DeployGuard는 Kubernetes 및 AWS 인프라의 공격 경로를 분석하고 최적의 보안 조치를 권장합니다.

## Scanner Lifecycle

1. **클러스터 등록**: `POST /api/v1/clusters` → API 토큰 발급
2. **Scanner 설치**: 발급된 토큰으로 Helm 차트 배포
3. **Polling**: `GET /api/v1/scans/pending` (Bearer 인증)
4. **업로드**: `POST /api/v1/scans/{scan_id}/upload-url`
5. **완료**: `POST /api/v1/scans/{scan_id}/complete` → Analysis 파이프라인 트리거
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


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    request.state.request_id = request_id
    start = perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        duration_ms = round((perf_counter() - start) * 1000, 2)
        if request.url.path not in _SKIP_LOG_PATHS:
            logger.exception(
                "Request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration_ms": duration_ms,
                    "request_id": request_id,
                },
            )
        raise

    response.headers["X-Request-ID"] = request_id
    duration_ms = round((perf_counter() - start) * 1000, 2)
    if request.url.path not in _SKIP_LOG_PATHS:
        logger.info(
            "Request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "request_id": request_id,
            },
        )
    return response

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
