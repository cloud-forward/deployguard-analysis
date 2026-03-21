"""
신규 Asset Inventory View Service (v1).

기존 InventoryService(AWS Discovery snapshot 기반 레거시)와 완전 분리된 별도 서비스.
이 파일은 기존 코드를 일체 수정하지 않으며, 신규 4개 API의 로직만 담당한다.

데이터 소스 전략 (MVP):
- cluster 기본 정보     → cluster_repository
- 자산 목록 / 카운트    → inventory_snapshot_repository (raw_result_json 기반)
- scanner coverage      → scan_repository.get_latest_completed_scans() 재활용
- last_analysis_at      → TODO: graph_snapshots 연동 후 실값 (현재 null)
- risk / entry / crown  → TODO: graph_nodes / attack_paths 연동 후 실값 (현재 placeholder)

MVP 임시값 표시:
- [임시값] 주석이 붙은 필드는 graph 연동 전까지 기본값(0, false, null, [])으로 반환
- 이는 의도된 설계이며, 2차 작업(graph 연동)에서 교체 예정
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException

from app.models.schemas import (
    InvAssetItem,
    InvAssetListResponse,
    InvRiskSpotlightResponse,
    InvRiskSummary,
    InvScannerCoverageDetail,
    InvScannerCoverageStatus,
    InvScannerItem,
    InvScannerStatusResponse,
    InvSummaryResponse,
)

# =============================================================================
# 상수 정의
# =============================================================================

# node_type → domain 매핑
K8S_TYPES: frozenset[str] = frozenset({
    "pod", "service", "serviceaccount", "node",
    "secret", "ingress", "role", "clusterrole",
})
AWS_TYPES: frozenset[str] = frozenset({
    "ec2", "s3", "rds", "iam_role", "iam_user", "security_group", "image",
})

# node_type → 관련 scanner 매핑 (coverage 근사 계산용)
NODE_TYPE_TO_SCANNERS: dict[str, list[str]] = {
    "pod": ["k8s", "image"],
    "service": ["k8s"],
    "serviceaccount": ["k8s"],
    "node": ["k8s"],
    "secret": ["k8s"],
    "ingress": ["k8s"],
    "role": ["k8s"],
    "clusterrole": ["k8s"],
    "ec2": ["aws"],
    "s3": ["aws"],
    "rds": ["aws"],
    "iam_role": ["aws"],
    "iam_user": ["aws"],
    "security_group": ["aws"],
    "image": ["image"],
}

# scanner_type → 표시명 매핑
SCANNER_DISPLAY_NAMES: dict[str, str] = {
    "k8s": "K8s Scanner (DG-K8s)",
    "aws": "AWS Scanner (DG-Cloud)",
    "image": "Image Scanner (DG-Image)",
}

# raw_result_json key → (asset_type, domain) 매핑
# inventory_snapshot의 raw_result_json 구조 기반
SNAPSHOT_KEY_MAP: list[tuple[str, str, str]] = [
    # (json_key, asset_type, domain)
    ("iam_roles",     "iam_role",       "aws"),
    ("iam_users",     "iam_user",       "aws"),
    ("s3_buckets",    "s3",             "aws"),
    ("rds_instances", "rds",            "aws"),
    ("ec2_instances", "ec2",            "aws"),
]


# =============================================================================
# 헬퍼
# =============================================================================

def _compute_coverage_status(
    scanner_type: str,
    completed_scans: dict,
) -> InvScannerCoverageStatus:
    """scan_records 기반 근사 커버리지 계산."""
    if scanner_type in completed_scans:
        return InvScannerCoverageStatus.covered
    return InvScannerCoverageStatus.not_covered


def _asset_scanner_coverage(
    node_type: str,
    completed_scans: dict,
) -> dict[str, str]:
    """
    node_type 기반으로 관련 scanner를 매핑하고,
    각 scanner의 coverage 상태를 반환한다.

    N/A (해당 없음) 케이스:
    - S3는 k8s/image scanner와 무관 → 해당 키 자체를 포함하지 않음
    - 이렇게 하면 프론트에서 key 없으면 N/A 처리 가능
    """
    related = NODE_TYPE_TO_SCANNERS.get(node_type.lower(), ["aws"])
    return {
        scanner: _compute_coverage_status(scanner, completed_scans).value
        for scanner in related
    }


def _extract_name_from_raw(asset_type: str, raw: dict[str, Any]) -> str:
    """raw_result_json 내 자산 dict에서 표시명 추출."""
    if asset_type == "ec2":
        return raw.get("instance_id", "unknown")
    if asset_type == "s3":
        return raw.get("name", "unknown")
    if asset_type == "rds":
        return raw.get("identifier", "unknown")
    if asset_type == "iam_role":
        return raw.get("name", "unknown")
    if asset_type == "iam_user":
        return raw.get("username", "unknown")
    return raw.get("name", raw.get("id", "unknown"))


def _build_node_id(asset_type: str, name: str, raw: dict[str, Any]) -> str:
    """자산 식별자 생성. 기존 build_ec2_item 등의 패턴과 일치."""
    if asset_type == "ec2":
        return f"ec2:{raw.get('instance_id', name)}"
    if asset_type == "s3":
        return f"s3:{name}"
    if asset_type == "rds":
        return f"rds:{name}"
    if asset_type == "iam_role":
        return f"iam-role:{name}"
    if asset_type == "iam_user":
        return f"iam-user:{name}"
    return f"{asset_type}:{name}"


def _build_metadata(asset_type: str, raw: dict[str, Any]) -> dict[str, Any]:
    """자산 타입별 metadata 필드 추출."""
    if asset_type == "ec2":
        return {
            "instance_id": raw.get("instance_id"),
            "private_ip": raw.get("private_ip"),
            "iam_instance_profile": raw.get("iam_instance_profile"),
            "security_groups": raw.get("security_groups", []),
            "metadata_options": raw.get("metadata_options", {}),
        }
    if asset_type == "s3":
        return {
            "arn": raw.get("arn"),
            "public_access_block": raw.get("public_access_block"),
            "encryption": raw.get("encryption"),
            "versioning": raw.get("versioning"),
            "logging_enabled": raw.get("logging_enabled"),
        }
    if asset_type == "rds":
        return {
            "arn": raw.get("arn"),
            "engine": raw.get("engine"),
            "engine_version": raw.get("engine_version"),
            "storage_encrypted": raw.get("storage_encrypted"),
            "publicly_accessible": raw.get("publicly_accessible"),
            "vpc_security_groups": raw.get("vpc_security_groups", []),
        }
    if asset_type == "iam_role":
        return {
            "arn": raw.get("arn"),
            "is_irsa": raw.get("is_irsa"),
            "attached_policies": raw.get("attached_policies", []),
            "inline_policies": raw.get("inline_policies", []),
        }
    if asset_type == "iam_user":
        return {
            "arn": raw.get("arn"),
            "has_mfa": raw.get("has_mfa"),
            "access_keys": raw.get("access_keys", []),
            "attached_policies": raw.get("attached_policies", []),
        }
    return {}


def _region_from_cluster(cluster: Any, asset_type: str) -> Optional[str]:
    """S3, IAM처럼 region 없는 자산은 None 반환."""
    no_region_types = {"s3", "iam_role", "iam_user"}
    if asset_type in no_region_types:
        return None
    return getattr(cluster, "aws_region", None)


# =============================================================================
# InventoryViewService
# =============================================================================

class InventoryViewService:
    """
    신규 Asset Inventory View API 서비스.

    주입 의존성:
    - cluster_repository       : 클러스터 기본 정보
    - scan_repository          : scan_records → coverage 근사 계산
    - snapshot_repository      : raw_result_json → 자산 목록/카운트 (MVP fallback)
    """

    def __init__(
        self,
        cluster_repository,
        scan_repository,
        snapshot_repository,
    ) -> None:
        self._clusters = cluster_repository
        self._scans = scan_repository
        self._snapshots = snapshot_repository

    # ------------------------------------------------------------------
    # 내부 공통 헬퍼
    # ------------------------------------------------------------------

    async def _get_cluster_or_404(self, cluster_id: str):
        cluster = await self._clusters.get_by_id(cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        return cluster

    async def _get_completed_scans(self, cluster_id: str) -> dict:
        """scan_records 기반 최신 completed 스캔 반환. 없으면 빈 dict."""
        try:
            return await self._scans.get_latest_completed_scans(cluster_id)
        except Exception:
            return {}

    async def _get_latest_snapshot(self, cluster_id: str):
        """최신 inventory_snapshot 반환. 없으면 None."""
        return await self._snapshots.get_latest_by_cluster(cluster_id)

    def _build_aws_counts_from_snapshot(self, raw: dict[str, Any]) -> dict[str, int]:
        """raw_result_json에서 AWS 자산 타입별 카운트 집계."""
        counts: dict[str, int] = {}
        for json_key, asset_type, _ in SNAPSHOT_KEY_MAP:
            items = raw.get(json_key, [])
            if isinstance(items, list) and items:
                counts[asset_type] = len(items)
        return counts

    def _build_all_assets_from_snapshot(
        self,
        raw: dict[str, Any],
        cluster: Any,
        completed_scans: dict,
        last_scan_at_str: Optional[str],
    ) -> list[InvAssetItem]:
        """raw_result_json 전체를 순회해 InvAssetItem 리스트 생성."""
        items: list[InvAssetItem] = []
        account_id: str = getattr(cluster, "aws_account_id", "") or ""

        for json_key, asset_type, domain in SNAPSHOT_KEY_MAP:
            for raw_asset in raw.get(json_key, []):
                if not isinstance(raw_asset, dict):
                    continue
                name = _extract_name_from_raw(asset_type, raw_asset)
                node_id = _build_node_id(asset_type, name, raw_asset)
                region = _region_from_cluster(cluster, asset_type)
                coverage = _asset_scanner_coverage(asset_type, completed_scans)
                metadata = _build_metadata(asset_type, raw_asset)

                items.append(InvAssetItem(
                    node_id=node_id,
                    node_type=asset_type,
                    domain=domain,
                    name=name,
                    namespace=None,          # AWS 자산은 namespace 없음
                    account_id=account_id or None,
                    region=region,
                    is_entry_point=False,    # [임시값] graph 미연동
                    is_crown_jewel=False,    # [임시값] graph 미연동
                    base_risk=None,          # [임시값] graph 미연동
                    scanner_coverage=coverage,
                    metadata=metadata,
                    timestamps={
                        "last_scan_at": last_scan_at_str,
                        "last_analysis_at": None,  # [임시값] graph 미연동
                    },
                ))
        return items

    # ------------------------------------------------------------------
    # GET /inventory/summary
    # ------------------------------------------------------------------

    async def get_summary(self, cluster_id: str) -> InvSummaryResponse:
        cluster = await self._get_cluster_or_404(cluster_id)
        completed_scans = await self._get_completed_scans(cluster_id)
        snapshot = await self._get_latest_snapshot(cluster_id)

        # 자산 카운트 (snapshot 기반)
        aws_resources: dict[str, int] = {}
        total_node_count = 0
        if snapshot is not None:
            raw = snapshot.raw_result_json or {}
            aws_resources = self._build_aws_counts_from_snapshot(raw)
            total_node_count = sum(aws_resources.values())

        # scanner coverage (scan_records 기반 근사)
        scanner_coverage: dict[str, InvScannerCoverageDetail] = {}
        for scanner_type in ("k8s", "aws", "image"):
            record = completed_scans.get(scanner_type)
            if record is not None:
                scanner_coverage[scanner_type] = InvScannerCoverageDetail(
                    status=InvScannerCoverageStatus.covered,
                    last_scan_at=getattr(record, "completed_at", None),
                    scan_id=getattr(record, "scan_id", None),
                )
            else:
                scanner_coverage[scanner_type] = InvScannerCoverageDetail(
                    status=InvScannerCoverageStatus.not_covered,
                    last_scan_at=None,
                    scan_id=None,
                )

        return InvSummaryResponse(
            cluster_id=cluster_id,
            cluster_name=getattr(cluster, "name", cluster_id),
            last_analysis_at=None,          # [임시값] graph_snapshots 미연동
            total_node_count=total_node_count,
            k8s_resources={},               # [임시값] K8s scanner 미연동
            aws_resources=aws_resources,
            scanner_coverage=scanner_coverage,
            risk_summary=InvRiskSummary(),  # [임시값] graph 미연동 → 전부 0
        )

    # ------------------------------------------------------------------
    # GET /inventory/assets
    # ------------------------------------------------------------------

    async def get_assets(
        self,
        cluster_id: str,
        domain: Optional[str] = None,
        node_type: Optional[str] = None,
        is_entry_point: Optional[bool] = None,
        is_crown_jewel: Optional[bool] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> InvAssetListResponse:
        # page_size 상한
        page_size = min(page_size, 200)

        cluster = await self._get_cluster_or_404(cluster_id)
        completed_scans = await self._get_completed_scans(cluster_id)
        snapshot = await self._get_latest_snapshot(cluster_id)

        if snapshot is None:
            return InvAssetListResponse(
                graph_id=None,
                total_count=0,
                page=page,
                page_size=page_size,
                assets=[],
            )

        raw = snapshot.raw_result_json or {}
        last_scan_at_str: Optional[str] = None
        if snapshot.scanned_at is not None:
            last_scan_at_str = snapshot.scanned_at.isoformat()

        all_assets = self._build_all_assets_from_snapshot(
            raw, cluster, completed_scans, last_scan_at_str
        )

        # 필터 적용
        filtered = all_assets

        if domain is not None:
            domain_lower = domain.lower()
            if domain_lower not in ("k8s", "aws"):
                raise HTTPException(
                    status_code=400,
                    detail="domain must be one of: k8s, aws",
                )
            filtered = [a for a in filtered if a.domain == domain_lower]

        if node_type is not None:
            filtered = [a for a in filtered if a.node_type == node_type.lower()]

        # is_entry_point / is_crown_jewel 필터
        # MVP: 모두 False이므로 true 필터링 시 결과 없음 → 의도된 동작
        if is_entry_point is not None:
            filtered = [a for a in filtered if a.is_entry_point == is_entry_point]

        if is_crown_jewel is not None:
            filtered = [a for a in filtered if a.is_crown_jewel == is_crown_jewel]

        total_count = len(filtered)

        # 페이지네이션
        offset = (page - 1) * page_size
        paged = filtered[offset: offset + page_size]

        return InvAssetListResponse(
            graph_id=None,      # [임시값] graph_snapshots 미연동
            total_count=total_count,
            page=page,
            page_size=page_size,
            assets=paged,
        )

    # ------------------------------------------------------------------
    # GET /inventory/risk-spotlight
    # ------------------------------------------------------------------

    async def get_risk_spotlight(self, cluster_id: str) -> InvRiskSpotlightResponse:
        """
        [MVP 임시값]
        graph_nodes.is_entry_point / is_crown_jewel 미연동.
        entry_points, crown_jewels 모두 빈 배열 반환.

        TODO (2차 작업):
        - GraphSnapshot latest completed 조회
        - graph_nodes WHERE is_entry_point=true → entry_points
        - graph_nodes WHERE is_crown_jewel=true → crown_jewels
        - attack_paths 집계 → attack_path_count, reachable_crown_jewel_count
        """
        await self._get_cluster_or_404(cluster_id)

        return InvRiskSpotlightResponse(
            graph_id=None,          # [임시값]
            entry_points=[],        # [임시값] graph 미연동
            crown_jewels=[],        # [임시값] graph 미연동
        )

    # ------------------------------------------------------------------
    # GET /inventory/scanner-status
    # ------------------------------------------------------------------

    async def get_scanner_status(self, cluster_id: str) -> InvScannerStatusResponse:
        await self._get_cluster_or_404(cluster_id)
        completed_scans = await self._get_completed_scans(cluster_id)

        scanners: list[InvScannerItem] = []
        for scanner_type in ("k8s", "aws", "image"):
            record = completed_scans.get(scanner_type)
            display_name = SCANNER_DISPLAY_NAMES.get(scanner_type, scanner_type)

            if record is not None:
                scanners.append(InvScannerItem(
                    scanner_type=scanner_type,
                    display_name=display_name,
                    status="active",
                    last_scan_at=getattr(record, "completed_at", None),
                    scan_id=getattr(record, "scan_id", None),
                    coverage_status=InvScannerCoverageStatus.covered,
                    resources_collected=None,   # TODO: scan result 연동 후 채움
                ))
            else:
                scanners.append(InvScannerItem(
                    scanner_type=scanner_type,
                    display_name=display_name,
                    status="inactive",
                    last_scan_at=None,
                    scan_id=None,
                    coverage_status=InvScannerCoverageStatus.not_covered,
                    resources_collected=None,
                ))

        return InvScannerStatusResponse(scanners=scanners)
