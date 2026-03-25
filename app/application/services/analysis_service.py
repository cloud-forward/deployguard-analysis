"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
import asyncio
import logging
import json
from typing import Dict, Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.domain.repositories.scan_repository import ScanRepository
from app.application.services.s3_service import S3Service

from app.core.graph_builder import GraphBuilder
from app.core.path_finder import PathFinder
from app.core.remediation_optimizer import RemediationOptimizer
from app.core.risk_engine import RiskEngine
from app.models.schemas import (
    AnalysisJobDetailResponse,
    AnalysisResultLinksResponse,
    AnalysisResultResponse,
    AnalysisResultSummaryResponse,
    AnalysisJobResponse,
    AnalysisJobSummaryResponse,
    AttackGraphSeverity,
    AttackPathListItemResponse,
    ClusterAnalysisJobListResponse,
    RemediationRecommendationListItemResponse,
)
from src.facts.extractors.k8s_extractor import K8sFactExtractor
from src.facts.extractors.aws_extractor import AWSFactExtractor
from src.facts.extractors.lateral_move_extractor import LateralMoveExtractor
from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    AccessKeyScan,
    EC2InstanceScan,
    IAMRoleScan,
    IAMUserScan,
    RDSInstanceScan,
    S3BucketScan,
    SecurityGroupScan,
)
from src.graph.builders.build_result_types import AWSBuildResult, K8sBuildResult
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder
from src.graph.builders.iam_policy_parser import parse_all_roles, parse_all_users
from src.graph.builders.k8s_graph_builder import K8sGraphBuilder
from src.graph.builders.unified_graph_builder import UnifiedGraphBuilder

logger = logging.getLogger(__name__)

MAX_HOPS = 10
MAX_ATTACK_PATHS = 100
PREVIEW_LIMIT = 5
SEVERITY_ORDER = {severity.value: idx for idx, severity in enumerate(AttackGraphSeverity)}


def _context(**kwargs):
    return {key: value for key, value in kwargs.items() if value is not None}


class AnalysisService:
    def __init__(
        self,
        jobs_repo: AnalysisJobRepository,
        scan_repo: ScanRepository,
        s3_service: S3Service | None = None,
        db: AsyncSession | None = None,
    ) -> None:
        self._jobs = jobs_repo
        self._scans = scan_repo
        self._s3 = s3_service
        self._db = db
        self._k8s_extractor = K8sFactExtractor()
        self._aws_extractor = AWSFactExtractor()
        self._lateral_extractor = LateralMoveExtractor()
        self._bridge_builder = IRSABridgeBuilder()
        self._graph_builder = GraphBuilder()
        self._unified_graph_builder = UnifiedGraphBuilder()
        self._path_finder = PathFinder()
        self._risk_engine = RiskEngine()
        self._remediation_optimizer = RemediationOptimizer()

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        job_id = await self._jobs.create_job(request.target_id, _params_dict(request))
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis started for target {request.target_id}",
        )

    async def create_analysis_job(
        self,
        k8s_scan_id: str | None = None,
        aws_scan_id: str | None = None,
        image_scan_id: str | None = None,
        user_id: str | None = None,
    ) -> AnalysisJobResponse:
        resolved = await self._resolve_analysis_job_inputs(
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )
        normalized_cluster_id = str(UUID(resolved["cluster_id"]))
        expected_scans = resolved["expected_scans"]
        selected_scan_ids = resolved["selected_scan_ids"]
        job_id = await self._jobs.create_analysis_job(
            cluster_id=normalized_cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
            expected_scans=expected_scans,
            user_id=user_id,
        )
        for scan_id in selected_scan_ids:
            await self._scans.set_analysis_run_id(scan_id, job_id)

        return AnalysisJobResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis job created for cluster {normalized_cluster_id}",
        )

    async def list_analysis_jobs(
        self,
        cluster_id: str,
        status: str | None = None,
    ) -> ClusterAnalysisJobListResponse:
        jobs = await self._jobs.list_analysis_jobs(cluster_id=cluster_id, status=status)
        items = [self._to_analysis_job_summary(job) for job in jobs]
        return ClusterAnalysisJobListResponse(items=items, total=len(items))

    async def get_analysis_job(self, job_id: str) -> AnalysisJobDetailResponse:
        job = await self._jobs.get_analysis_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Analysis job not found: {job_id}")
        return self._to_analysis_job_detail(job)

    async def get_analysis_result(self, job_id: str) -> AnalysisResultResponse:
        job = await self._jobs.get_analysis_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Analysis job not found: {job_id}")

        job_detail = self._to_analysis_job_detail(job)
        graph_id = str(job.graph_id) if job.graph_id is not None else None

        summary = await self._get_analysis_result_summary(graph_id)
        attack_paths_preview = (
            await self._get_attack_paths_preview(graph_id, limit=PREVIEW_LIMIT)
            if graph_id else
            []
        )
        remediation_preview = (
            await self._get_remediation_preview(graph_id, limit=PREVIEW_LIMIT)
            if graph_id else
            []
        )

        return AnalysisResultResponse(
            job=job_detail,
            summary=summary,
            attack_paths_preview=attack_paths_preview,
            remediation_preview=remediation_preview,
            links=self._build_analysis_result_links(job_detail),
        )

    async def execute_analysis_job(self, job_id: str) -> Dict[str, Any]:
        job = await self._jobs.get_analysis_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Analysis job not found: {job_id}")
        persisted_job_id = str(job.id)
        cluster_id = str(job.cluster_id)
        k8s_scan_id = job.k8s_scan_id
        aws_scan_id = job.aws_scan_id
        image_scan_id = job.image_scan_id

        await self._jobs.mark_running(persisted_job_id, current_step="fact_extraction")
        try:
            result = await self.execute_analysis(
                cluster_id=cluster_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                analysis_job_id=persisted_job_id,
            )
        except Exception as exc:
            await self._jobs.rollback()
            await self._jobs.mark_failed(persisted_job_id, str(exc))
            raise

        await self._jobs.mark_completed(persisted_job_id, result.get("stats", {}))
        return result

    async def execute_analysis_debug(
        self,
        k8s_scan_id: str | None = None,
        aws_scan_id: str | None = None,
        image_scan_id: str | None = None,
    ) -> Dict[str, Any]:
        resolved_inputs = await self._resolve_analysis_job_inputs(
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )
        return await self.execute_analysis(
            cluster_id=resolved_inputs["cluster_id"],
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
            require_cluster_match=False,
        )

    async def execute_analysis(
        self,
        cluster_id: str,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        analysis_job_id: str | None = None,
        require_cluster_match: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute full attack path analysis.
        
        Args:
            cluster_id: Target cluster ID
            k8s_scan_id: K8s scan ID
            aws_scan_id: AWS scan ID
            image_scan_id: Image scan ID
        
        Returns:
            Analysis result with attack paths
        """
        logger.info(
            "Starting analysis execution",
            extra=_context(
                cluster_id=cluster_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                analysis_job_id=analysis_job_id,
            ),
        )
        
        try:
            if not any((k8s_scan_id, aws_scan_id, image_scan_id)):
                raise ValueError("At least one scan ID is required for analysis execution")

            await self._update_step(analysis_job_id, "fact_extraction")
            k8s_scan = (
                await self._load_scan_data(cluster_id, k8s_scan_id, SCANNER_TYPE_K8S, require_cluster_match=require_cluster_match)
                if k8s_scan_id else
                {"cluster_id": cluster_id, "scanner_type": SCANNER_TYPE_K8S, "scan_id": None}
            )
            aws_scan = (
                await self._load_scan_data(cluster_id, aws_scan_id, SCANNER_TYPE_AWS, require_cluster_match=False)
                if aws_scan_id else
                {"cluster_id": cluster_id, "scanner_type": SCANNER_TYPE_AWS, "scan_id": None}
            )
            image_scan = (
                await self._load_scan_data(cluster_id, image_scan_id, SCANNER_TYPE_IMAGE, require_cluster_match=require_cluster_match)
                if image_scan_id else
                {"cluster_id": cluster_id, "scanner_type": SCANNER_TYPE_IMAGE, "scan_id": None}
            )
            extracted_k8s_facts = (
                await asyncio.to_thread(self._extract_k8s_facts, k8s_scan)
                if k8s_scan_id else
                []
            )

            k8s_result = (
                await asyncio.to_thread(self._build_k8s_result, k8s_scan, k8s_scan_id)
                if k8s_scan_id else
                K8sBuildResult(metadata={"cluster_id": cluster_id})
            )
            aws_scan_result = (
                await asyncio.to_thread(self._coerce_aws_scan_result, aws_scan, aws_scan_id)
                if aws_scan_id else
                AWSScanResult(scan_id="", aws_account_id="", scanned_at="")
            )
            bridge_result = await asyncio.to_thread(
                self._bridge_builder.build,
                k8s_scan,
                aws_scan_result,
            )
            extracted_aws_facts = (
                await asyncio.to_thread(
                    self._extract_aws_facts,
                    aws_scan_result,
                    k8s_scan if k8s_scan_id else None,
                )
                if aws_scan_id else
                []
            )
            aws_result = (
                await asyncio.to_thread(self._build_aws_result, aws_scan_result, bridge_result)
                if aws_scan_id else
                AWSBuildResult(metadata={"scan_id": None, "account_id": None})
            )
            extracted_facts = [*extracted_k8s_facts, *extracted_aws_facts]
            unified_result = self._unified_graph_builder.build(k8s_result, aws_result)

            logger.info(
                "Unified graph assembled from domain results",
                extra=_context(
                    cluster_id=cluster_id,
                    k8s_nodes=len(k8s_result.nodes),
                    aws_nodes=len(aws_result.nodes),
                    unified_nodes=len(unified_result.nodes),
                    unified_edges=len(unified_result.edges),
                ),
            )

            # Step 3: Adapt unified graph for existing NetworkX consumers
            await self._update_step(analysis_job_id, "graph_building")
            graph = await self._graph_builder.build_from_unified_result(unified_result)
            
            # Step 4: Find attack paths
            entry_points = self._graph_builder.get_entry_points()
            crown_jewels = self._graph_builder.get_crown_jewels()
            
            logger.info(
                f"Graph built: {len(entry_points)} entry points, {len(crown_jewels)} crown jewels",
                extra=_context(cluster_id=cluster_id),
            )
            
            await self._update_step(analysis_job_id, "path_discovery")
            paths = self._path_finder.find_all_paths(
                graph,
                entry_points,
                crown_jewels,
                max_path_length=MAX_HOPS,
                max_paths=MAX_ATTACK_PATHS,
            )
            valid_paths = [path for path in paths if self._is_valid_attack_path(path)]
            
            # Step 5: Calculate risk scores
            await self._update_step(analysis_job_id, "risk_calculation")
            enriched_paths = []
            for path in valid_paths:
                path_id = f"path:{len(enriched_paths)}:{'->'.join(path)}"
                risk_details = self._risk_engine.calculate_path_risk_details(graph, path)
                edges = self._path_finder.get_path_edges(graph, path)
                
                enriched_paths.append({
                    "path_id": path_id,
                    "path": path,
                    "risk_score": risk_details["risk_score"],
                    "raw_final_risk": risk_details["raw_final_risk"],
                    "length": len(path),
                    "edges": [
                        {"source": src, "target": tgt, "type": edge_type}
                        for src, tgt, edge_type in edges
                    ],
                })

            enriched_paths = self._refine_attack_paths(enriched_paths)
            preferred_graph_id = str(
                unified_result.metadata.get("k8s", {}).get("graph_id")
                or k8s_result.metadata.get("graph_id")
                or ""
            ) or None
            graph_id = await self._jobs.persist_attack_paths(
                cluster_id=cluster_id,
                graph_id=preferred_graph_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                attack_paths=enriched_paths,
            )
            await self._jobs.persist_facts(
                cluster_id=cluster_id,
                analysis_job_id=analysis_job_id,
                graph_id=graph_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                facts=extracted_facts,
            )
            await self._jobs.persist_graph(graph_id=graph_id, graph=graph)
            await self._jobs.finalize_graph_snapshot(
                graph_id=graph_id,
                node_count=graph.number_of_nodes(),
                edge_count=graph.number_of_edges(),
                entry_point_count=len(entry_points),
                crown_jewel_count=len(crown_jewels),
            )
            await self._update_step(analysis_job_id, "optimization")
            remediation_optimization = self._remediation_optimizer.optimize(enriched_paths, graph)
            await self._jobs.persist_remediation_recommendations(
                cluster_id=cluster_id,
                graph_id=graph_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                remediation_optimization=remediation_optimization,
            )
            
            result = {
                "cluster_id": cluster_id,
                "analysis_job_id": analysis_job_id,
                "scan_ids": {
                    "k8s": k8s_scan_id,
                    "aws": aws_scan_id,
                    "image": image_scan_id,
                },
                "stats": {
                    "facts": {
                        "total": len(extracted_facts),
                        "errors": 0,
                        "warnings": len(bridge_result.warnings) + len(unified_result.warnings),
                    },
                    "graph": {
                        "nodes": graph.number_of_nodes(),
                        "edges": graph.number_of_edges(),
                        "entry_points": len(entry_points),
                        "crown_jewels": len(crown_jewels),
                    },
                    "paths": {
                        "total": len(valid_paths),
                        "returned": len(enriched_paths),
                    },
                },
                "attack_paths": enriched_paths,
                "remediation_optimization": remediation_optimization,
            }
            
            logger.info(
                f"Analysis complete: {len(enriched_paths)} attack paths found",
                extra=_context(cluster_id=cluster_id, analysis_job_id=analysis_job_id),
            )
            
            return result
            
        except Exception as e:
            logger.error(
                f"Analysis execution failed: {str(e)}",
                extra=_context(
                    cluster_id=cluster_id,
                    analysis_job_id=analysis_job_id,
                    error_type=type(e).__name__,
                ),
            )
            raise

    async def _update_step(self, analysis_job_id: str | None, current_step: str) -> None:
        if analysis_job_id is None:
            return
        await self._jobs.update_current_step(analysis_job_id, current_step)

    async def _get_analysis_result_summary(self, graph_id: str | None) -> AnalysisResultSummaryResponse:
        if not graph_id:
            return AnalysisResultSummaryResponse()

        db = self._require_db()
        graph_snapshot = (
            await db.execute(
                text(
                    """
                    SELECT id, completed_at, status, node_count, edge_count, entry_point_count, crown_jewel_count
                    FROM graph_snapshots
                    WHERE id = :graph_id
                    LIMIT 1
                    """
                ),
                {"graph_id": graph_id},
            )
        ).mappings().first()

        attack_path_count = await self._count_rows("attack_paths", graph_id)
        remediation_count = await self._count_rows("remediation_recommendations", graph_id)

        if graph_snapshot is None:
            return AnalysisResultSummaryResponse(
                graph_id=graph_id,
                attack_path_count=attack_path_count,
                remediation_recommendation_count=remediation_count,
            )

        return AnalysisResultSummaryResponse(
            graph_id=str(graph_snapshot["id"]),
            generated_at=graph_snapshot.get("completed_at"),
            graph_status=self._normalize_optional_str(graph_snapshot.get("status")),
            node_count=self._normalize_int(graph_snapshot.get("node_count")) or 0,
            edge_count=self._normalize_int(graph_snapshot.get("edge_count")) or 0,
            entry_point_count=self._normalize_int(graph_snapshot.get("entry_point_count")) or 0,
            crown_jewel_count=self._normalize_int(graph_snapshot.get("crown_jewel_count")) or 0,
            attack_path_count=attack_path_count,
            remediation_recommendation_count=remediation_count,
        )

    async def _get_attack_paths_preview(
        self,
        graph_id: str,
        limit: int = PREVIEW_LIMIT,
    ) -> list[AttackPathListItemResponse]:
        db = self._require_db()
        columns = await self._get_table_columns("attack_paths")
        if not columns:
            return []

        id_col = self._pick_column(columns, "path_id", "attack_path_id", "id")
        if not id_col:
            return []

        title_col = self._pick_column(columns, "title", "name")
        severity_col = self._pick_column(columns, "severity", "risk_level")
        risk_score_col = self._pick_column(columns, "risk_score")
        raw_final_risk_col = self._pick_column(columns, "raw_final_risk")
        hop_count_col = self._pick_column(columns, "hop_count")
        entry_col = self._pick_column(columns, "entry_node_id")
        target_col = self._pick_column(columns, "target_node_id")
        node_ids_col = self._pick_column(columns, "node_ids", "path_nodes", "path_node_ids")

        select_parts = [
            f"{id_col} AS path_id",
            f"{title_col} AS title" if title_col else "NULL AS title",
            f"{severity_col} AS risk_level" if severity_col else "NULL AS risk_level",
            f"{risk_score_col} AS risk_score" if risk_score_col else "NULL AS risk_score",
            f"{raw_final_risk_col} AS raw_final_risk" if raw_final_risk_col else "NULL AS raw_final_risk",
            f"{hop_count_col} AS hop_count" if hop_count_col else "NULL AS hop_count",
            f"{entry_col} AS entry_node_id" if entry_col else "NULL AS entry_node_id",
            f"{target_col} AS target_node_id" if target_col else "NULL AS target_node_id",
            f"{node_ids_col} AS node_ids" if node_ids_col else "NULL AS node_ids",
        ]

        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT {", ".join(select_parts)}
                    FROM attack_paths
                    WHERE graph_id = :graph_id
                    """
                ),
                {"graph_id": graph_id},
            )
        ).mappings().all()

        items = [
            AttackPathListItemResponse(
                path_id=str(row["path_id"]),
                title=self._normalize_path_title(
                    row.get("title"),
                    row.get("path_id"),
                    self._normalize_string_list(row.get("node_ids")),
                ),
                risk_level=self._normalize_severity(row.get("risk_level")),
                risk_score=self._normalize_float(row.get("risk_score")),
                raw_final_risk=self._normalize_float(row.get("raw_final_risk")),
                hop_count=self._normalize_int(row.get("hop_count")) or max(len(self._normalize_string_list(row.get("node_ids"))) - 1, 0),
                entry_node_id=self._normalize_optional_str(row.get("entry_node_id")),
                target_node_id=self._normalize_optional_str(row.get("target_node_id")),
                node_ids=self._normalize_string_list(row.get("node_ids")),
            )
            for row in rows
        ]
        items.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item.risk_level, 99),
                -(item.raw_final_risk or -1.0),
                item.hop_count,
                item.path_id,
            )
        )
        return items[:limit]

    async def _get_remediation_preview(
        self,
        graph_id: str,
        limit: int = PREVIEW_LIMIT,
    ) -> list[RemediationRecommendationListItemResponse]:
        db = self._require_db()
        columns = await self._get_table_columns("remediation_recommendations")
        if not columns:
            return []

        id_col = self._pick_column(columns, "recommendation_id", "id")
        rank_col = self._pick_column(columns, "recommendation_rank", "rank", "position")
        if not id_col or not rank_col:
            return []

        source_col = self._pick_column(columns, "edge_source", "source_node_id", "source")
        target_col = self._pick_column(columns, "edge_target", "target_node_id", "target")
        type_col = self._pick_column(columns, "edge_type", "type")
        fix_type_col = self._pick_column(columns, "fix_type")
        fix_desc_col = self._pick_column(columns, "fix_description", "description")
        blocked_ids_col = self._pick_column(columns, "blocked_path_ids")
        blocked_indices_col = self._pick_column(columns, "blocked_path_indices")
        fix_cost_col = self._pick_column(columns, "fix_cost")
        edge_score_col = self._pick_column(columns, "edge_score", "score")
        covered_risk_col = self._pick_column(columns, "covered_risk")
        cumulative_col = self._pick_column(columns, "cumulative_risk_reduction")
        metadata_col = self._pick_column(columns, "metadata", "properties", "attributes")

        select_parts = [
            f"{id_col} AS recommendation_id",
            f"{rank_col} AS recommendation_rank",
            f"{source_col} AS edge_source" if source_col else "NULL AS edge_source",
            f"{target_col} AS edge_target" if target_col else "NULL AS edge_target",
            f"{type_col} AS edge_type" if type_col else "NULL AS edge_type",
            f"{fix_type_col} AS fix_type" if fix_type_col else "NULL AS fix_type",
            f"{fix_desc_col} AS fix_description" if fix_desc_col else "NULL AS fix_description",
            f"{blocked_ids_col} AS blocked_path_ids" if blocked_ids_col else "NULL AS blocked_path_ids",
            f"{blocked_indices_col} AS blocked_path_indices" if blocked_indices_col else "NULL AS blocked_path_indices",
            f"{fix_cost_col} AS fix_cost" if fix_cost_col else "NULL AS fix_cost",
            f"{edge_score_col} AS edge_score" if edge_score_col else "NULL AS edge_score",
            f"{covered_risk_col} AS covered_risk" if covered_risk_col else "NULL AS covered_risk",
            f"{cumulative_col} AS cumulative_risk_reduction" if cumulative_col else "NULL AS cumulative_risk_reduction",
            f"{metadata_col} AS metadata" if metadata_col else "NULL AS metadata",
        ]

        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT {", ".join(select_parts)}
                    FROM remediation_recommendations
                    WHERE graph_id = :graph_id
                    """
                ),
                {"graph_id": graph_id},
            )
        ).mappings().all()

        items = [
            RemediationRecommendationListItemResponse(
                recommendation_id=str(row["recommendation_id"]),
                recommendation_rank=self._normalize_int(row.get("recommendation_rank")) or 0,
                edge_source=self._normalize_optional_str(row.get("edge_source")),
                edge_target=self._normalize_optional_str(row.get("edge_target")),
                edge_type=self._normalize_optional_str(row.get("edge_type")),
                fix_type=self._normalize_optional_str(row.get("fix_type")),
                fix_description=self._normalize_optional_str(row.get("fix_description")),
                blocked_path_ids=self._normalize_string_list(row.get("blocked_path_ids")),
                blocked_path_indices=self._normalize_int_list(row.get("blocked_path_indices")),
                fix_cost=self._normalize_float(row.get("fix_cost")),
                edge_score=self._normalize_float(row.get("edge_score")),
                covered_risk=self._normalize_float(row.get("covered_risk")),
                cumulative_risk_reduction=self._normalize_float(row.get("cumulative_risk_reduction")),
                metadata=self._normalize_object(row.get("metadata")),
            )
            for row in rows
        ]
        items.sort(
            key=lambda item: (
                item.recommendation_rank,
                -(item.cumulative_risk_reduction or -1.0),
                item.recommendation_id,
            )
        )
        return items[:limit]

    def _build_analysis_result_links(self, job: AnalysisJobDetailResponse) -> AnalysisResultLinksResponse:
        cluster_id = job.cluster_id
        return AnalysisResultLinksResponse(
            analysis_job=f"/api/v1/analysis/jobs/{job.job_id}",
            attack_graph=f"/api/v1/clusters/{cluster_id}/attack-graph" if cluster_id else None,
            attack_paths=f"/api/v1/clusters/{cluster_id}/attack-paths" if cluster_id else None,
            remediation_recommendations=(
                f"/api/v1/clusters/{cluster_id}/remediation-recommendations" if cluster_id else None
            ),
        )

    @staticmethod
    def _to_analysis_job_summary(job) -> AnalysisJobSummaryResponse:
        return AnalysisJobSummaryResponse(
            job_id=job.id,
            status=job.status,
            current_step=job.current_step,
            k8s_scan_id=job.k8s_scan_id,
            aws_scan_id=job.aws_scan_id,
            image_scan_id=job.image_scan_id,
            expected_scans=list(job.expected_scans or []),
            error_message=job.error_message,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            graph_id=job.graph_id,
        )

    @classmethod
    def _to_analysis_job_detail(cls, job) -> AnalysisJobDetailResponse:
        summary = cls._to_analysis_job_summary(job)
        return AnalysisJobDetailResponse(
            cluster_id=job.cluster_id,
            **summary.model_dump(),
        )

    def _refine_attack_paths(self, paths: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """
        Prune weaker near-duplicate paths and apply explicit deterministic ranking.

        Current v1 heuristic:
        - exact duplicates are already suppressed in PathFinder
        - for the same entry/target pair, drop a path when a shorter or equal-hop path
          with no lower risk is a strict ordered subsequence of it
        - rank remaining paths by risk desc, hop count asc, generic-allows count asc, path_id asc
        """
        grouped: dict[tuple[str | None, str | None], list[Dict[str, Any]]] = {}
        for item in paths:
            path_nodes = [str(node_id) for node_id in item.get("path", [])]
            key = (
                path_nodes[0] if path_nodes else None,
                path_nodes[-1] if path_nodes else None,
            )
            grouped.setdefault(key, []).append(item)

        refined: list[Dict[str, Any]] = []
        for group in grouped.values():
            survivors: list[Dict[str, Any]] = []
            ordered_group = sorted(group, key=self._attack_path_sort_key)
            for candidate in ordered_group:
                if any(self._path_dominates(existing, candidate) for existing in survivors):
                    continue
                survivors.append(candidate)
            refined.extend(survivors)

        refined.sort(key=self._attack_path_sort_key)
        return refined

    def _attack_path_sort_key(self, item: Dict[str, Any]) -> tuple[float, int, int, str]:
        path = [str(node_id) for node_id in item.get("path", [])]
        raw_final_risk = item.get("raw_final_risk")
        try:
            risk = float(raw_final_risk)
        except (TypeError, ValueError):
            risk = 0.0

        edges = item.get("edges", [])
        generic_allows_count = sum(
            1 for edge in edges if str(edge.get("type", "")).strip().lower() == "allows"
        )

        return (
            -risk,
            max(len(path) - 1, 0),
            generic_allows_count,
            str(item.get("path_id", "")),
        )

    @staticmethod
    def _is_valid_attack_path(path: list[Any]) -> bool:
        normalized_path = [str(node_id) for node_id in path]
        return len(normalized_path) > 1 and normalized_path[0] != normalized_path[-1]

    def _path_dominates(self, dominant: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
        dominant_path = [str(node_id) for node_id in dominant.get("path", [])]
        candidate_path = [str(node_id) for node_id in candidate.get("path", [])]

        if dominant_path == candidate_path or len(dominant_path) >= len(candidate_path):
            return False
        if not dominant_path or not candidate_path:
            return False
        if dominant_path[0] != candidate_path[0] or dominant_path[-1] != candidate_path[-1]:
            return False

        dominant_risk = self._coerce_float(dominant.get("raw_final_risk"))
        candidate_risk = self._coerce_float(candidate.get("raw_final_risk"))
        if dominant_risk < candidate_risk:
            return False

        if not self._is_ordered_subsequence(dominant_path, candidate_path):
            return False

        return True

    @staticmethod
    def _is_ordered_subsequence(smaller: list[str], larger: list[str]) -> bool:
        iterator = iter(larger)
        return all(item in iterator for item in smaller)

    @staticmethod
    def _coerce_float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _require_db(self) -> AsyncSession:
        if self._db is None:
            raise RuntimeError("AnalysisService requires a database session for persisted result reads")
        return self._db

    async def _get_table_columns(self, table_name: str) -> set[str]:
        db = self._require_db()
        conn = await db.connection()

        def _inspect_columns(sync_conn):
            inspector = inspect(sync_conn)
            if not inspector.has_table(table_name):
                return set()
            return {column["name"] for column in inspector.get_columns(table_name)}

        return await conn.run_sync(_inspect_columns)

    async def _count_rows(self, table_name: str, graph_id: str) -> int:
        db = self._require_db()
        columns = await self._get_table_columns(table_name)
        if not columns or "graph_id" not in columns:
            return 0
        row = (
            await db.execute(
                text(f"SELECT COUNT(*) AS cnt FROM {table_name} WHERE graph_id = :graph_id"),
                {"graph_id": graph_id},
            )
        ).mappings().first()
        return int(row["cnt"]) if row else 0

    @staticmethod
    def _pick_column(columns: set[str], *candidates: str) -> str | None:
        for candidate in candidates:
            if candidate in columns:
                return candidate
        return None

    @staticmethod
    def _normalize_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_optional_str(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

    @staticmethod
    def _normalize_string_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return []
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        return []

    @staticmethod
    def _normalize_int_list(value: Any) -> list[int]:
        if value is None:
            return []
        if isinstance(value, list):
            candidates = value
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return []
            if not isinstance(parsed, list):
                return []
            candidates = parsed
        else:
            return []

        normalized: list[int] = []
        for item in candidates:
            try:
                normalized.append(int(item))
            except (TypeError, ValueError):
                continue
        return normalized

    @staticmethod
    def _normalize_object(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            return dict(parsed) if isinstance(parsed, dict) else {}
        return {}

    @staticmethod
    def _normalize_severity(value: Any) -> AttackGraphSeverity:
        normalized = str(value or "").strip().lower()
        if normalized in AttackGraphSeverity._value2member_map_:
            return AttackGraphSeverity(normalized)
        return AttackGraphSeverity.none

    @staticmethod
    def _normalize_path_title(value: Any, path_id: Any, node_ids: list[str]) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if node_ids:
            return f"{node_ids[0]} -> {node_ids[-1]}"
        return f"Path {path_id}"

    def _build_k8s_result(self, k8s_scan: Dict[str, Any], scan_id: str):
        return K8sGraphBuilder().build(
            self._extract_k8s_facts(k8s_scan),
            k8s_scan,
            scan_id=scan_id,
        )

    def _extract_k8s_facts(self, k8s_scan: Dict[str, Any]):
        k8s_facts = self._k8s_extractor.extract(k8s_scan)
        lateral_facts = self._lateral_extractor.extract(k8s_scan)
        return self._annotate_fact_scan_id(
            [*k8s_facts, *lateral_facts],
            scan_id=self._coerce_scan_id(k8s_scan.get("scan_id")),
        )

    def _build_aws_result(self, aws_scan: AWSScanResult, bridge_result):
        policy_results = parse_all_roles(aws_scan.iam_roles) if aws_scan.iam_roles else None
        user_policy_results = parse_all_users(aws_scan.iam_users) if aws_scan.iam_users else None
        return AWSGraphBuilder(
            account_id=aws_scan.aws_account_id,
            scan_id=aws_scan.scan_id,
        ).build_with_bridge_result(
            aws_scan,
            bridge_result,
            policy_results=policy_results,
            user_policy_results=user_policy_results,
        )

    def _extract_aws_facts(self, aws_scan: AWSScanResult, k8s_scan: Dict[str, Any] | None):
        facts, _bridge_output = self._aws_extractor.extract_with_debug(
            aws_scan,
            k8s_scan=k8s_scan or {"scan_id": None},
        )
        return self._annotate_fact_scan_id(
            facts,
            scan_id=self._coerce_scan_id(getattr(aws_scan, "scan_id", None)),
        )

    @staticmethod
    def _coerce_scan_id(value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @staticmethod
    def _annotate_fact_scan_id(facts, scan_id: str | None):
        for fact in facts:
            setattr(fact, "_persisted_scan_id", scan_id)
        return facts

    def _coerce_aws_scan_result(self, aws_scan: Dict[str, Any] | AWSScanResult, scan_id: str) -> AWSScanResult:
        if isinstance(aws_scan, AWSScanResult):
            return aws_scan

        return AWSScanResult(
            scan_id=aws_scan.get("scan_id", scan_id),
            aws_account_id=aws_scan.get("aws_account_id", ""),
            scanned_at=aws_scan.get("scanned_at", ""),
            iam_roles=[
                role if isinstance(role, IAMRoleScan) else IAMRoleScan(
                    name=role.get("name") or role.get("role_name", ""),
                    arn=role.get("arn", ""),
                    is_irsa=role.get("is_irsa", False),
                    irsa_oidc_issuer=role.get("irsa_oidc_issuer"),
                    attached_policies=role.get("attached_policies", []),
                    inline_policies=role.get("inline_policies", []),
                    trust_policy=role.get("trust_policy", {}),
                )
                for role in aws_scan.get("iam_roles", [])
            ],
            s3_buckets=[
                bucket if isinstance(bucket, S3BucketScan) else S3BucketScan(**bucket)
                for bucket in aws_scan.get("s3_buckets", [])
            ],
            rds_instances=[
                instance if isinstance(instance, RDSInstanceScan) else RDSInstanceScan(**instance)
                for instance in aws_scan.get("rds_instances", [])
            ],
            ec2_instances=[
                instance if isinstance(instance, EC2InstanceScan) else EC2InstanceScan(**instance)
                for instance in aws_scan.get("ec2_instances", [])
            ],
            security_groups=[
                sg if isinstance(sg, SecurityGroupScan) else SecurityGroupScan(**sg)
                for sg in aws_scan.get("security_groups", [])
            ],
            region=aws_scan.get("region"),
            iam_users=[
                user if isinstance(user, IAMUserScan) else IAMUserScan(
                    **{
                        **user,
                        "access_keys": [
                            key if isinstance(key, AccessKeyScan) else AccessKeyScan(**key)
                            for key in user.get("access_keys", [])
                        ],
                    }
                )
                for user in aws_scan.get("iam_users", [])
            ],
        )

    async def _load_scan_data(
        self,
        cluster_id: str,
        scan_id: str,
        scanner_type: str,
        require_cluster_match: bool = True,
    ) -> Dict[str, Any]:
        """Load explicit scan raw JSON from S3 using the selected scan record."""
        if self._s3 is None:
            raise RuntimeError("S3 service is not configured for analysis execution")

        record = await self._scans.get_by_scan_id(scan_id)
        if record is None:
            raise ValueError(f"Scan record not found: {scan_id}")
        if require_cluster_match and str(record.cluster_id) != str(cluster_id):
            raise ValueError(f"Scan {scan_id} does not belong to cluster {cluster_id}")
        if record.scanner_type != scanner_type:
            raise ValueError(
                f"Scan {scan_id} has scanner_type={record.scanner_type}, expected {scanner_type}"
            )
        if record.status != "completed":
            raise ValueError(f"Scan {scan_id} is not completed")

        s3_keys = list(record.s3_keys or [])
        if not s3_keys:
            raise ValueError(f"Scan {scan_id} has no raw scan payload in s3_keys")

        selected_key = self._select_scan_payload_key(s3_keys)
        payload = await asyncio.to_thread(self._s3.load_json, selected_key)
        if not isinstance(payload, dict):
            raise ValueError(f"Scan {scan_id} raw payload must be a JSON object")

        payload.setdefault("scan_id", scan_id)
        payload.setdefault("cluster_id", str(cluster_id))
        payload.setdefault("scanner_type", scanner_type)
        return payload

    async def _resolve_analysis_job_inputs(
        self,
        *,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
    ) -> Dict[str, Any]:
        selected_scans = [
            (SCANNER_TYPE_K8S, "k8s_scan_id", k8s_scan_id),
            (SCANNER_TYPE_AWS, "aws_scan_id", aws_scan_id),
            (SCANNER_TYPE_IMAGE, "image_scan_id", image_scan_id),
        ]
        provided = [(scanner_type, field_name, scan_id) for scanner_type, field_name, scan_id in selected_scans if scan_id]
        if not provided:
            raise HTTPException(status_code=422, detail="At least one scan ID must be provided")

        records_by_field: dict[str, Any] = {}
        expected_scans: list[str] = []
        for scanner_type, field_name, scan_id in provided:
            record = await self._scans.get_by_scan_id(scan_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
            if record.scanner_type != scanner_type:
                raise HTTPException(
                    status_code=400,
                    detail=f"Scan {scan_id} has scanner_type={record.scanner_type}, expected {scanner_type} for {field_name}",
                )
            if record.status != "completed":
                raise HTTPException(
                    status_code=400,
                    detail=f"Scan {scan_id} is not completed",
                )
            records_by_field[field_name] = record
            expected_scans.append(scanner_type)

        k8s_record = records_by_field.get("k8s_scan_id")
        image_record = records_by_field.get("image_scan_id")
        if k8s_record is not None and image_record is not None and str(k8s_record.cluster_id) != str(image_record.cluster_id):
            raise HTTPException(
                status_code=400,
                detail=(
                    "k8s_scan_id and image_scan_id must belong to the same cluster: "
                    f"{k8s_scan_id}={k8s_record.cluster_id}, {image_scan_id}={image_record.cluster_id}"
                ),
            )

        representative_cluster_id = None
        aws_record = records_by_field.get("aws_scan_id")
        if k8s_record is not None:
            representative_cluster_id = str(k8s_record.cluster_id)
        elif image_record is not None:
            representative_cluster_id = str(image_record.cluster_id)
        else:
            representative_cluster_id = str(aws_record.cluster_id)

        return {
            "cluster_id": representative_cluster_id,
            "expected_scans": expected_scans,
            "selected_scan_ids": [scan_id for _, _, scan_id in provided],
        }

    @staticmethod
    def _select_scan_payload_key(s3_keys: list[str]) -> str:
        if len(s3_keys) == 1:
            return s3_keys[0]
        for s3_key in s3_keys:
            if s3_key.endswith("-snapshot.json"):
                return s3_key
        raise ValueError("Unable to determine raw scan payload key from s3_keys")


def _params_dict(request: AnalysisRequest) -> Dict[str, Any]:
    return {"depth": request.depth, **(request.parameters or {})}
