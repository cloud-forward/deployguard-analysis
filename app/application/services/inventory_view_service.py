"""
신규 Asset Inventory View Service (v1).

기존 InventoryService(AWS Discovery snapshot 기반 레거시)와 완전 분리된 별도 서비스.
이 파일은 기존 코드를 일체 수정하지 않으며, 신규 4개 API의 로직만 담당한다.

데이터 소스 전략:
- cluster 기본 정보     → cluster_repository
- 자산 목록 / 카운트    → graph_nodes (graph 있을 때) / inventory_snapshot (fallback)
- scanner coverage      → scan_repository.get_latest_completed_scans()
- last_analysis_at      → graph_snapshots.completed_at
- risk / entry / crown  → graph_nodes / attack_paths
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schemas import (
    InvAssetItem,
    InvAssetListResponse,
    InvRiskSpotlightItem,
    InvRiskSpotlightResponse,
    InvRiskSummary,
    InvScannerCoverageDetail,
    InvScannerCoverageStatus,
    InvScannerItem,
    InvScannerStatusResponse,
    InvSummaryResponse,
)

logger = logging.getLogger(__name__)

# =============================================================================
# 상수 정의
# =============================================================================

NODE_TYPE_TO_SCANNERS: dict[str, list[str]] = {
    "pod": ["k8s", "image"],
    "service": ["k8s"],
    "service_account": ["k8s"],
    "node": ["k8s"],
    "secret": ["k8s"],
    "ingress": ["k8s"],
    "role": ["k8s"],
    "cluster_role": ["k8s"],
    "ec2_instance": ["aws"],
    "s3_bucket": ["aws"],
    "rds": ["aws"],
    "iam_role": ["aws"],
    "iam_user": ["aws"],
    "security_group": ["aws"],
    "container_image": ["image"],
}

SCANNER_DISPLAY_NAMES: dict[str, str] = {
    "k8s": "K8s Scanner (DG-K8s)",
    "aws": "AWS Scanner (DG-Cloud)",
    "image": "Image Scanner (DG-Image)",
}

SNAPSHOT_KEY_MAP: list[tuple[str, str, str]] = [
    ("iam_roles",     "iam_role",  "aws"),
    ("iam_users",     "iam_user",  "aws"),
    ("s3_buckets",    "s3",        "aws"),
    ("rds_instances", "rds",       "aws"),
    ("ec2_instances", "ec2",       "aws"),
]

# graph_nodes.node_type → domain
GRAPH_NODE_TYPE_TO_DOMAIN: dict[str, str] = {
    "pod": "k8s", "service_account": "k8s", "role": "k8s", "cluster_role": "k8s",
    "secret": "k8s", "service": "k8s", "ingress": "k8s", "node": "k8s",
    "container_image": "k8s",
    "iam_role": "aws", "iam_user": "aws", "s3_bucket": "aws", "rds": "aws",
    "security_group": "aws", "ec2_instance": "aws",
}


# =============================================================================
# 헬퍼
# =============================================================================

def _compute_coverage_status(scanner_type: str, completed_scans: dict) -> InvScannerCoverageStatus:
    if scanner_type in completed_scans:
        return InvScannerCoverageStatus.covered
    return InvScannerCoverageStatus.not_covered


def _asset_scanner_coverage(node_type: str, completed_scans: dict) -> dict[str, str]:
    related = NODE_TYPE_TO_SCANNERS.get(node_type.lower(), ["aws"])
    return {s: _compute_coverage_status(s, completed_scans).value for s in related}


def _node_name_from_node_id(node_id: str) -> str:
    parts = node_id.split(":")
    return parts[-1] if parts else node_id


def _extract_name_from_raw(asset_type: str, raw: dict[str, Any]) -> str:
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
    if asset_type == "ec2":
        return {"instance_id": raw.get("instance_id"), "private_ip": raw.get("private_ip"),
                "iam_instance_profile": raw.get("iam_instance_profile"),
                "security_groups": raw.get("security_groups", []),
                "metadata_options": raw.get("metadata_options", {})}
    if asset_type == "s3":
        return {"arn": raw.get("arn"), "public_access_block": raw.get("public_access_block"),
                "encryption": raw.get("encryption"), "versioning": raw.get("versioning"),
                "logging_enabled": raw.get("logging_enabled")}
    if asset_type == "rds":
        return {"arn": raw.get("arn"), "engine": raw.get("engine"),
                "engine_version": raw.get("engine_version"),
                "storage_encrypted": raw.get("storage_encrypted"),
                "publicly_accessible": raw.get("publicly_accessible"),
                "vpc_security_groups": raw.get("vpc_security_groups", [])}
    if asset_type == "iam_role":
        return {"arn": raw.get("arn"), "is_irsa": raw.get("is_irsa"),
                "attached_policies": raw.get("attached_policies", []),
                "inline_policies": raw.get("inline_policies", [])}
    if asset_type == "iam_user":
        return {"arn": raw.get("arn"), "has_mfa": raw.get("has_mfa"),
                "access_keys": raw.get("access_keys", []),
                "attached_policies": raw.get("attached_policies", [])}
    return {}


def _region_from_cluster(cluster: Any, asset_type: str) -> Optional[str]:
    if asset_type in {"s3", "iam_role", "iam_user"}:
        return None
    return getattr(cluster, "aws_region", None)


# =============================================================================
# InventoryViewService
# =============================================================================

class InventoryViewService:
    def __init__(self, cluster_repository, scan_repository, snapshot_repository, db: AsyncSession) -> None:
        self._clusters = cluster_repository
        self._scans = scan_repository
        self._snapshots = snapshot_repository
        self._db = db

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    async def _get_cluster_or_404(self, cluster_id: str, user_id: str | None = None):
        cluster = await self._clusters.get_by_id(cluster_id, user_id=user_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        return cluster

    async def _get_completed_scans(self, cluster_id: str) -> dict:
        try:
            return await self._scans.get_latest_completed_scans(str(cluster_id))
        except Exception as e:
            logger.error("_get_completed_scans 에러: %s", e, exc_info=True)
            return {}

    async def _get_latest_snapshot(self, cluster_id: str):
        return await self._snapshots.get_latest_by_cluster(cluster_id)

    async def _get_latest_graph_snapshot(self, cluster_id: str) -> Optional[Any]:
        try:
            result = await self._db.execute(
                text("""
                    SELECT id, completed_at, node_count, edge_count,
                           entry_point_count, crown_jewel_count
                    FROM graph_snapshots
                    WHERE cluster_id = :cluster_id AND status = 'completed'
                    ORDER BY created_at DESC
                    LIMIT 1
                """),
                {"cluster_id": cluster_id},
            )
            return result.mappings().first()
        except Exception as e:
            logger.error("_get_latest_graph_snapshot 에러: %s", e, exc_info=True)
            return None

    async def _get_graph_node_type_counts(self, graph_id: str) -> dict[str, int]:
        try:
            result = await self._db.execute(
                text("SELECT node_type, COUNT(*) as cnt FROM graph_nodes WHERE graph_id = :gid GROUP BY node_type"),
                {"gid": graph_id},
            )
            return {row["node_type"]: row["cnt"] for row in result.mappings().all()}
        except Exception as e:
            logger.error("_get_graph_node_type_counts 에러: %s", e, exc_info=True)
            return {}

    async def _get_critical_path_count(self, graph_id: str) -> int:
        try:
            result = await self._db.execute(
                text("SELECT COUNT(*) as cnt FROM attack_paths WHERE graph_id = :gid AND risk_level = 'critical'"),
                {"gid": graph_id},
            )
            row = result.mappings().first()
            return row["cnt"] if row else 0
        except Exception as e:
            logger.error("_get_critical_path_count 에러: %s", e, exc_info=True)
            return 0

    async def _get_entry_point_nodes(self, graph_id: str, limit: int = 10) -> list[Any]:
        try:
            result = await self._db.execute(
                text("""
                    SELECT node_id, node_type, namespace, base_risk, metadata
                    FROM graph_nodes
                    WHERE graph_id = :gid AND is_entry_point = true
                    ORDER BY base_risk DESC LIMIT :limit
                """),
                {"gid": graph_id, "limit": limit},
            )
            return result.mappings().all()
        except Exception as e:
            logger.error("_get_entry_point_nodes 에러: %s", e, exc_info=True)
            return []

    async def _get_crown_jewel_nodes(self, graph_id: str, limit: int = 10) -> list[Any]:
        try:
            result = await self._db.execute(
                text("""
                    SELECT node_id, node_type, namespace, base_risk, metadata
                    FROM graph_nodes
                    WHERE graph_id = :gid AND is_crown_jewel = true
                    ORDER BY base_risk DESC LIMIT :limit
                """),
                {"gid": graph_id, "limit": limit},
            )
            return result.mappings().all()
        except Exception as e:
            logger.error("_get_crown_jewel_nodes 에러: %s", e, exc_info=True)
            return []

    async def _get_attack_path_count_by_node(self, graph_id: str, node_id: str, role: str) -> int:
        try:
            col = "entry_node_id" if role == "entry" else "target_node_id"
            result = await self._db.execute(
                text(f"SELECT COUNT(*) as cnt FROM attack_paths WHERE graph_id = :gid AND {col} = :nid"),
                {"gid": graph_id, "nid": node_id},
            )
            row = result.mappings().first()
            return row["cnt"] if row else 0
        except Exception as e:
            logger.error("_get_attack_path_count_by_node 에러: %s", e, exc_info=True)
            return 0

    async def _get_reachable_crown_jewel_count(self, graph_id: str, entry_node_id: str) -> int:
        try:
            result = await self._db.execute(
                text("""
                    SELECT COUNT(DISTINCT ap.target_node_id) as cnt
                    FROM attack_paths ap
                    JOIN graph_nodes gn ON gn.node_id = ap.target_node_id AND gn.graph_id = ap.graph_id
                    WHERE ap.graph_id = :gid AND ap.entry_node_id = :nid AND gn.is_crown_jewel = true
                """),
                {"gid": graph_id, "nid": entry_node_id},
            )
            row = result.mappings().first()
            return row["cnt"] if row else 0
        except Exception as e:
            logger.error("_get_reachable_crown_jewel_count 에러: %s", e, exc_info=True)
            return 0

    async def _get_all_graph_nodes(self, graph_id: str, domain: Optional[str] = None,
                                    node_type: Optional[str] = None,
                                    is_entry_point: Optional[bool] = None,
                                    is_crown_jewel: Optional[bool] = None) -> list[Any]:
        try:
            conditions = ["graph_id = :gid"]
            params: dict[str, Any] = {"gid": graph_id}
            if node_type is not None:
                conditions.append("node_type = :node_type")
                params["node_type"] = node_type.lower()
            if is_entry_point is not None:
                conditions.append("is_entry_point = :is_entry_point")
                params["is_entry_point"] = is_entry_point
            if is_crown_jewel is not None:
                conditions.append("is_crown_jewel = :is_crown_jewel")
                params["is_crown_jewel"] = is_crown_jewel

            where = " AND ".join(conditions)
            result = await self._db.execute(
                text(f"""
                    SELECT node_id, node_type, namespace, is_entry_point, is_crown_jewel, base_risk, metadata
                    FROM graph_nodes WHERE {where} ORDER BY base_risk DESC
                """),
                params,
            )
            rows = result.mappings().all()
            if domain is not None:
                rows = [r for r in rows if GRAPH_NODE_TYPE_TO_DOMAIN.get(r["node_type"], "aws") == domain.lower()]
            return rows
        except Exception as e:
            logger.error("_get_all_graph_nodes 에러: %s", e, exc_info=True)
            return []

    def _build_aws_counts_from_snapshot(self, raw: dict[str, Any]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for json_key, asset_type, _ in SNAPSHOT_KEY_MAP:
            items = raw.get(json_key, [])
            if isinstance(items, list) and items:
                counts[asset_type] = len(items)
        return counts

    def _build_all_assets_from_snapshot(self, raw, cluster, completed_scans, last_scan_at_str) -> list[InvAssetItem]:
        items: list[InvAssetItem] = []
        account_id: str = getattr(cluster, "aws_account_id", "") or ""
        for json_key, asset_type, domain in SNAPSHOT_KEY_MAP:
            for raw_asset in raw.get(json_key, []):
                if not isinstance(raw_asset, dict):
                    continue
                name = _extract_name_from_raw(asset_type, raw_asset)
                node_id = _build_node_id(asset_type, name, raw_asset)
                items.append(InvAssetItem(
                    node_id=node_id, node_type=asset_type, domain=domain, name=name,
                    namespace=None, account_id=account_id or None,
                    region=_region_from_cluster(cluster, asset_type),
                    is_entry_point=False, is_crown_jewel=False, base_risk=None,
                    scanner_coverage=_asset_scanner_coverage(asset_type, completed_scans),
                    metadata=_build_metadata(asset_type, raw_asset),
                    timestamps={"last_scan_at": last_scan_at_str, "last_analysis_at": None},
                ))
        return items

    # ------------------------------------------------------------------
    # GET /inventory/summary
    # ------------------------------------------------------------------

    async def get_summary(self, cluster_id: str, user_id: str | None = None) -> InvSummaryResponse:
        cluster = await self._get_cluster_or_404(cluster_id, user_id=user_id)
        completed_scans = await self._get_completed_scans(cluster_id)
        graph_snapshot = await self._get_latest_graph_snapshot(cluster_id)

        k8s_resources: dict[str, int] = {}
        aws_resources: dict[str, int] = {}
        total_node_count = 0
        last_analysis_at = None
        risk_summary = InvRiskSummary()

        if graph_snapshot is not None:
            graph_id = str(graph_snapshot["id"])
            last_analysis_at = graph_snapshot["completed_at"]

            type_counts = await self._get_graph_node_type_counts(graph_id)
            for ntype, cnt in type_counts.items():
                if GRAPH_NODE_TYPE_TO_DOMAIN.get(ntype, "aws") == "k8s":
                    k8s_resources[ntype] = cnt
                else:
                    aws_resources[ntype] = cnt
            total_node_count = sum(type_counts.values())

            critical_path_count = await self._get_critical_path_count(graph_id)
            risk_summary = InvRiskSummary(
                entry_point_count=graph_snapshot["entry_point_count"],
                crown_jewel_count=graph_snapshot["crown_jewel_count"],
                critical_path_count=critical_path_count,
            )
        else:
            # graph 없으면 snapshot fallback
            snapshot = await self._get_latest_snapshot(cluster_id)
            if snapshot is not None:
                raw = snapshot.raw_result_json or {}
                aws_resources = self._build_aws_counts_from_snapshot(raw)
                total_node_count = sum(aws_resources.values())

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
                    last_scan_at=None, scan_id=None,
                )

        return InvSummaryResponse(
            cluster_id=cluster_id,
            cluster_name=getattr(cluster, "name", cluster_id),
            last_analysis_at=last_analysis_at,
            total_node_count=total_node_count,
            k8s_resources=k8s_resources,
            aws_resources=aws_resources,
            scanner_coverage=scanner_coverage,
            risk_summary=risk_summary,
        )

    # ------------------------------------------------------------------
    # GET /inventory/assets
    # ------------------------------------------------------------------

    async def get_assets(self, cluster_id: str, user_id: str | None = None, domain: Optional[str] = None,
                          node_type: Optional[str] = None, is_entry_point: Optional[bool] = None,
                          is_crown_jewel: Optional[bool] = None, page: int = 1, page_size: int = 20) -> InvAssetListResponse:
        page_size = min(page_size, 200)
        if domain is not None and domain.lower() not in ("k8s", "aws"):
            raise HTTPException(status_code=400, detail="domain must be one of: k8s, aws")

        cluster = await self._get_cluster_or_404(cluster_id, user_id=user_id)
        completed_scans = await self._get_completed_scans(cluster_id)
        graph_snapshot = await self._get_latest_graph_snapshot(cluster_id)

        if graph_snapshot is not None:
            graph_id = str(graph_snapshot["id"])
            rows = await self._get_all_graph_nodes(graph_id, domain, node_type, is_entry_point, is_crown_jewel)
            total_count = len(rows)
            paged = rows[(page - 1) * page_size: (page - 1) * page_size + page_size]

            last_analysis_at_str = graph_snapshot["completed_at"].isoformat() if graph_snapshot["completed_at"] else None
            assets = [
                InvAssetItem(
                    node_id=r["node_id"],
                    node_type=r["node_type"],
                    domain=GRAPH_NODE_TYPE_TO_DOMAIN.get(r["node_type"], "aws"),
                    name=_node_name_from_node_id(r["node_id"]),
                    namespace=r["namespace"],
                    account_id=None, region=None,
                    is_entry_point=r["is_entry_point"],
                    is_crown_jewel=r["is_crown_jewel"],
                    base_risk=int(r["base_risk"] * 100) if r["base_risk"] is not None else None,
                    scanner_coverage=_asset_scanner_coverage(r["node_type"], completed_scans),
                    metadata=dict(r["metadata"]) if r["metadata"] else {},
                    timestamps={"last_scan_at": None, "last_analysis_at": last_analysis_at_str},
                )
                for r in paged
            ]
            return InvAssetListResponse(graph_id=graph_id, total_count=total_count,
                                         page=page, page_size=page_size, assets=assets)

        # fallback: snapshot
        snapshot = await self._get_latest_snapshot(cluster_id)
        if snapshot is None:
            return InvAssetListResponse(graph_id=None, total_count=0, page=page, page_size=page_size, assets=[])

        raw = snapshot.raw_result_json or {}
        last_scan_at_str = snapshot.scanned_at.isoformat() if snapshot.scanned_at else None
        all_assets = self._build_all_assets_from_snapshot(raw, cluster, completed_scans, last_scan_at_str)

        filtered = all_assets
        if domain is not None:
            filtered = [a for a in filtered if a.domain == domain.lower()]
        if node_type is not None:
            filtered = [a for a in filtered if a.node_type == node_type.lower()]
        if is_entry_point is not None:
            filtered = [a for a in filtered if a.is_entry_point == is_entry_point]
        if is_crown_jewel is not None:
            filtered = [a for a in filtered if a.is_crown_jewel == is_crown_jewel]

        total_count = len(filtered)
        paged = filtered[(page - 1) * page_size: (page - 1) * page_size + page_size]
        return InvAssetListResponse(graph_id=None, total_count=total_count, page=page, page_size=page_size, assets=paged)

    # ------------------------------------------------------------------
    # GET /inventory/risk-spotlight
    # ------------------------------------------------------------------

    async def get_risk_spotlight(self, cluster_id: str, user_id: str | None = None) -> InvRiskSpotlightResponse:
        await self._get_cluster_or_404(cluster_id, user_id=user_id)
        graph_snapshot = await self._get_latest_graph_snapshot(cluster_id)

        if graph_snapshot is None:
            return InvRiskSpotlightResponse(graph_id=None, entry_points=[], crown_jewels=[])

        graph_id = str(graph_snapshot["id"])
        entry_rows = await self._get_entry_point_nodes(graph_id)
        crown_rows = await self._get_crown_jewel_nodes(graph_id)

        entry_points = []
        for row in entry_rows:
            nid = row["node_id"]
            entry_points.append(InvRiskSpotlightItem(
                node_id=nid,
                node_type=row["node_type"],
                domain=GRAPH_NODE_TYPE_TO_DOMAIN.get(row["node_type"], "aws"),
                name=_node_name_from_node_id(nid),
                namespace=row["namespace"],
                base_risk=int(row["base_risk"] * 100) if row["base_risk"] is not None else None,
                attack_path_count=await self._get_attack_path_count_by_node(graph_id, nid, "entry"),
                reachable_crown_jewel_count=await self._get_reachable_crown_jewel_count(graph_id, nid),
            ))

        crown_jewels = []
        for row in crown_rows:
            nid = row["node_id"]
            crown_jewels.append(InvRiskSpotlightItem(
                node_id=nid,
                node_type=row["node_type"],
                domain=GRAPH_NODE_TYPE_TO_DOMAIN.get(row["node_type"], "aws"),
                name=_node_name_from_node_id(nid),
                namespace=row["namespace"],
                base_risk=int(row["base_risk"] * 100) if row["base_risk"] is not None else None,
                attack_path_count=await self._get_attack_path_count_by_node(graph_id, nid, "target"),
                reachable_crown_jewel_count=None,
            ))

        return InvRiskSpotlightResponse(graph_id=graph_id, entry_points=entry_points, crown_jewels=crown_jewels)

    # ------------------------------------------------------------------
    # GET /inventory/scanner-status
    # ------------------------------------------------------------------

    async def get_scanner_status(self, cluster_id: str, user_id: str | None = None) -> InvScannerStatusResponse:
        await self._get_cluster_or_404(cluster_id, user_id=user_id)
        completed_scans = await self._get_completed_scans(cluster_id)

        scanners: list[InvScannerItem] = []
        for scanner_type in ("k8s", "aws", "image"):
            record = completed_scans.get(scanner_type)
            display_name = SCANNER_DISPLAY_NAMES.get(scanner_type, scanner_type)
            if record is not None:
                scanners.append(InvScannerItem(
                    scanner_type=scanner_type, display_name=display_name, status="active",
                    last_scan_at=getattr(record, "completed_at", None),
                    scan_id=getattr(record, "scan_id", None),
                    coverage_status=InvScannerCoverageStatus.covered, resources_collected=None,
                ))
            else:
                scanners.append(InvScannerItem(
                    scanner_type=scanner_type, display_name=display_name, status="inactive",
                    last_scan_at=None, scan_id=None,
                    coverage_status=InvScannerCoverageStatus.not_covered, resources_collected=None,
                ))

        return InvScannerStatusResponse(scanners=scanners)
