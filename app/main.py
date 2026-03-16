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

클러스터 등록: POST /api/v1/clusters

API 토큰 발급: scanner API 토큰은 클러스터 온보딩 과정에서 관리됨  
(이 서비스에서 별도의 공개 엔드포인트로 제공되지는 않음)

Scanner Helm 설치: 발급된 토큰을 사용하여 scanner 설치

Scanner polling:  
GET /api/v1/scans/pending  
Authorization: Bearer <api_token>

스캔 실행 및 결과 업로드:  
scanner가 POST /api/v1/scans/{scan_id}/upload-url 로 파일 업로드

완료 알림:  
scanner가 POST /api/v1/scans/{scan_id}/complete 호출

Analysis 파이프라인 단계:  
서비스가 scan 상태를 processing으로 전환하고  
현재 구현된 orchestration 체크(maybe_trigger_analysis)만 트리거

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
