from typing import Optional

from fastapi import APIRouter, Depends

from app.application.di import get_inventory_service, get_inventory_view_service
from app.application.services.inventory_service import InventoryService
from app.application.services.inventory_view_service import InventoryViewService
from app.models.schemas import (
    AssetDetailResponse,
    AssetInventoryListResponse,
    InvAssetListResponse,
    InvRiskSpotlightResponse,
    InvScannerStatusResponse,
    InvSummaryResponse,
)

router = APIRouter(tags=["Clusters"])


# ---------------------------------------------------------------------------
# 기존 레거시 API (AWS Discovery snapshot 기반) — 수정 금지
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/clusters/{cluster_id}/assets",
    response_model=AssetInventoryListResponse,
    status_code=200,
    summary="클러스터 Discovery Inventory 조회",
    description="지정한 클러스터의 최신 Discovery Inventory 스냅샷을 읽어 자산 목록을 반환합니다.",
    responses={
        200: {"description": "클러스터 자산 목록"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
    },
    tags=["Discovery Inventory"],
)
async def get_cluster_assets(
    cluster_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> AssetInventoryListResponse:
    return await service.get_cluster_assets(cluster_id)


@router.get(
    "/api/v1/assets/{asset_id:path}",
    response_model=AssetDetailResponse,
    status_code=200,
    summary="Discovery Inventory 자산 상세 조회",
    description="최신 Discovery Inventory 스냅샷들에서 자산을 찾아 상세 정보를 반환합니다.",
    responses={
        200: {"description": "자산 상세 정보"},
        404: {"description": "자산을 찾을 수 없습니다"},
    },
    tags=["Discovery Inventory"],
)
async def get_asset_detail(
    asset_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> AssetDetailResponse:
    return await service.get_asset_detail(asset_id)


# ---------------------------------------------------------------------------
# 신규 Asset Inventory View API (v1)
# 경로: /api/v1/clusters/{cluster_id}/inventory/*
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/clusters/{cluster_id}/inventory/summary",
    response_model=InvSummaryResponse,
    status_code=200,
    summary="[신규] Inventory Summary 조회",
    description=(
        "Summary Bar용. 전체 자산 수, K8s/AWS 타입별 집계, 스캐너 커버리지, 위험 요약을 반환합니다.\n\n"
        "**MVP 임시값 안내:**\n"
        "- `last_analysis_at`: graph_snapshots 미연동으로 null\n"
        "- `k8s_resources`: K8s scanner 미연동으로 빈 dict\n"
        "- `risk_summary`: graph/attack_paths 미연동으로 전부 0\n"
        "- `scanner_coverage`: scan_records 기반 근사값"
    ),
    tags=["Inventory (v1)"],
)
async def get_inventory_summary(
    cluster_id: str,
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> InvSummaryResponse:
    return await service.get_summary(cluster_id)


@router.get(
    "/api/v1/clusters/{cluster_id}/inventory/assets",
    response_model=InvAssetListResponse,
    status_code=200,
    summary="[신규] Inventory 자산 목록 조회",
    description=(
        "Asset Grid용. 필터/페이지네이션을 지원하는 자산 목록을 반환합니다.\n\n"
        "**MVP 임시값 안내:**\n"
        "- `is_entry_point`, `is_crown_jewel`: graph 미연동으로 항상 false\n"
        "- `base_risk`: graph 미연동으로 null\n"
        "- `graph_id`: graph_snapshots 미연동으로 null\n"
        "- `timestamps.last_analysis_at`: graph 미연동으로 null"
    ),
    tags=["Inventory (v1)"],
)
async def get_inventory_assets(
    cluster_id: str,
    domain: Optional[str] = None,
    node_type: Optional[str] = None,
    is_entry_point: Optional[bool] = None,
    is_crown_jewel: Optional[bool] = None,
    page: int = 1,
    page_size: int = 20,
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> InvAssetListResponse:
    return await service.get_assets(
        cluster_id=cluster_id,
        domain=domain,
        node_type=node_type,
        is_entry_point=is_entry_point,
        is_crown_jewel=is_crown_jewel,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/api/v1/clusters/{cluster_id}/inventory/risk-spotlight",
    response_model=InvRiskSpotlightResponse,
    status_code=200,
    summary="[신규] Risk Spotlight 조회",
    description=(
        "Risk Spotlight 패널용. Entry Point / Crown Jewel 목록을 반환합니다.\n\n"
        "**MVP 임시값 안내:**\n"
        "- `entry_points`, `crown_jewels`: graph_nodes 미연동으로 빈 배열\n"
        "- `graph_id`: graph_snapshots 미연동으로 null\n\n"
        "2차 작업(graph 연동) 이후 실값으로 교체 예정."
    ),
    tags=["Inventory (v1)"],
)
async def get_inventory_risk_spotlight(
    cluster_id: str,
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> InvRiskSpotlightResponse:
    return await service.get_risk_spotlight(cluster_id)


@router.get(
    "/api/v1/clusters/{cluster_id}/inventory/scanner-status",
    response_model=InvScannerStatusResponse,
    status_code=200,
    summary="[신규] Scanner Status 조회",
    description=(
        "Scanner Status Bar용. 스캐너별 최신 스캔 상태 및 커버리지를 반환합니다.\n\n"
        "**데이터 소스:** scan_records 기반 근사값 (MVP)\n"
        "- `resources_collected`: scan result 미연동으로 null\n"
        "- `coverage_status`: completed scan 존재 여부로 covered/not_covered 판정"
    ),
    tags=["Inventory (v1)"],
)
async def get_inventory_scanner_status(
    cluster_id: str,
    service: InventoryViewService = Depends(get_inventory_view_service),
) -> InvScannerStatusResponse:
    return await service.get_scanner_status(cluster_id)