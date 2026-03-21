"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
import logging
from typing import Dict, Any
from uuid import UUID

from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.domain.repositories.scan_repository import ScanRepository

# ✨ 새로 추가
from src.facts.orchestrator import FactOrchestrator
from app.core.graph_builder import GraphBuilder
from app.core.path_finder import PathFinder
from app.core.risk_engine import RiskEngine
from src.graph.builders.aws_scanner_types import IAMRoleScan, IAMUserScan
from src.graph.builders.iam_policy_parser import parse_all_roles, parse_all_users

logger = logging.getLogger(__name__)

REQUIRED_SCAN_TYPES = {SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE}


def _context(**kwargs):
    return {key: value for key, value in kwargs.items() if value is not None}


class AnalysisService:
    def __init__(
        self,
        jobs_repo: AnalysisJobRepository,
        scan_repo: ScanRepository,
    ) -> None:
        self._jobs = jobs_repo
        self._scans = scan_repo
        
        # ✨ 새로 추가: Fact 파이프라인 컴포넌트
        self._fact_orchestrator = FactOrchestrator()
        self._graph_builder = GraphBuilder()
        self._path_finder = PathFinder()
        self._risk_engine = RiskEngine()

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        job_id = await self._jobs.create_job(request.target_id, _params_dict(request))
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis started for target {request.target_id}",
        )

    # ✨ 새로 추가: 실제 분석 수행 메서드
    async def execute_analysis(
        self,
        cluster_id: str,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
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
            cluster_id=cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
        )
        
        try:
            # Step 1: Load scan data from S3
            k8s_scan = await self._load_scan_data(cluster_id, k8s_scan_id, SCANNER_TYPE_K8S)
            aws_scan = await self._load_scan_data(cluster_id, aws_scan_id, SCANNER_TYPE_AWS)
            image_scan = await self._load_scan_data(cluster_id, image_scan_id, SCANNER_TYPE_IMAGE)
            
            # Step 2: Extract facts
            fact_collection = await self._fact_orchestrator.extract_all(
                k8s_scan, aws_scan, image_scan
            )
            
            logger.info(
                f"Facts extracted: {len(fact_collection.facts)} valid facts",
                cluster_id=cluster_id,
            )
            
            # Step 3: Build graph
            policy_results, user_policy_results = self._build_aws_policy_analysis(aws_scan)
            graph = await self._graph_builder.build_from_facts(
                fact_collection.facts,
                k8s_scan=k8s_scan,
                scan_id=k8s_scan_id,
                aws_scan=aws_scan,
                policy_results=policy_results,
                user_policy_results=user_policy_results,
            )
            
            # Step 4: Find attack paths
            entry_points = self._graph_builder.get_entry_points()
            crown_jewels = self._graph_builder.get_crown_jewels()
            
            logger.info(
                f"Graph built: {len(entry_points)} entry points, {len(crown_jewels)} crown jewels",
                cluster_id=cluster_id,
            )
            
            paths = self._path_finder.find_all_paths(
                graph,
                entry_points,
                crown_jewels,
                max_path_length=10,
            )
            
            # Step 5: Calculate risk scores
            enriched_paths = []
            for path in paths[:100]:  # Limit to top 100
                risk_score = self._risk_engine.calculate_path_risk(graph, path)
                edges = self._path_finder.get_path_edges(graph, path)
                
                enriched_paths.append({
                    "path": path,
                    "risk_score": risk_score,
                    "length": len(path),
                    "edges": [
                        {"source": src, "target": tgt, "type": edge_type}
                        for src, tgt, edge_type in edges
                    ],
                })
            
            # Sort by risk score
            enriched_paths.sort(key=lambda x: x["risk_score"], reverse=True)
            
            result = {
                "cluster_id": cluster_id,
                "scan_ids": {
                    "k8s": k8s_scan_id,
                    "aws": aws_scan_id,
                    "image": image_scan_id,
                },
                "stats": {
                    "facts": {
                        "total": len(fact_collection.facts),
                        "errors": fact_collection.error_count,
                        "warnings": fact_collection.warning_count,
                    },
                    "graph": {
                        "nodes": graph.number_of_nodes(),
                        "edges": graph.number_of_edges(),
                        "entry_points": len(entry_points),
                        "crown_jewels": len(crown_jewels),
                    },
                    "paths": {
                        "total": len(paths),
                        "returned": len(enriched_paths),
                    },
                },
                "attack_paths": enriched_paths,
            }
            
            logger.info(
                f"Analysis complete: {len(enriched_paths)} attack paths found",
                cluster_id=cluster_id,
            )
            
            return result
            
        except Exception as e:
            logger.error(
                f"Analysis execution failed: {str(e)}",
                cluster_id=cluster_id,
                error_type=type(e).__name__,
            )
            raise

    async def _load_scan_data(
        self, cluster_id: str, scan_id: str, scanner_type: str
    ) -> Dict[str, Any]:
        """Load scan data from S3"""
        # TODO: Implement actual S3 loading
        # For now, return mock data structure
        return {
            "scan_id": scan_id,
            "cluster_id": cluster_id,
            "scanner_type": scanner_type,
            # Scanner-specific data will be loaded from S3
        }

    def _build_aws_policy_analysis(self, aws_scan: Dict[str, Any]):
        """Build optional IAM policy analysis inputs for AWS typed graph seeding."""
        iam_roles = self._typed_scan_list(aws_scan.get("iam_roles"), IAMRoleScan)
        iam_users = self._typed_scan_list(aws_scan.get("iam_users"), IAMUserScan)

        policy_results = parse_all_roles(iam_roles) if iam_roles else None
        user_policy_results = parse_all_users(iam_users) if iam_users else None
        return policy_results, user_policy_results

    def _typed_scan_list(self, items, cls):
        if not isinstance(items, list):
            return []

        typed_items = []
        for item in items:
            if isinstance(item, cls):
                typed_items.append(item)
            elif isinstance(item, dict):
                try:
                    typed_items.append(cls(**item))
                except TypeError:
                    continue
        return typed_items

    async def maybe_trigger_analysis(self, cluster_id: str | UUID, request_id: str | None = None) -> None:
        cluster_id_str = str(cluster_id)
        logger.info(
            "scan.analysis.trigger_check_invoked",
            extra=_context(request_id=request_id, cluster_id=cluster_id_str),
        )
        latest = await self._scans.get_latest_completed_scans(cluster_id_str)
        if not REQUIRED_SCAN_TYPES.issubset(latest.keys()):
            return
        normalized_cluster_id = str(UUID(cluster_id_str))
        job_id = await self._jobs.create_analysis_job(
            cluster_id=normalized_cluster_id,
            k8s_scan_id=latest[SCANNER_TYPE_K8S].scan_id,
            aws_scan_id=latest[SCANNER_TYPE_AWS].scan_id,
            image_scan_id=latest[SCANNER_TYPE_IMAGE].scan_id,
        )
        logger.info("Analysis job created: job_id=%s cluster_id=%s", job_id, normalized_cluster_id)
        
        # ✨ 새로 추가: 실제 분석 실행 트리거
        try:
            await self.execute_analysis(
                cluster_id=normalized_cluster_id,
                k8s_scan_id=latest[SCANNER_TYPE_K8S].scan_id,
                aws_scan_id=latest[SCANNER_TYPE_AWS].scan_id,
                image_scan_id=latest[SCANNER_TYPE_IMAGE].scan_id,
            )
        except Exception as e:
            logger.error(f"Analysis execution failed: {e}", exc_info=True)


def _params_dict(request: AnalysisRequest) -> Dict[str, Any]:
    return {"depth": request.depth, **(request.parameters or {})}
