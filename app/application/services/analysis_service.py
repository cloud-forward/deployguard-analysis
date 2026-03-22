"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Dict, Any
from uuid import UUID

from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.domain.repositories.scan_repository import ScanRepository

from app.core.graph_builder import GraphBuilder
from app.core.path_finder import PathFinder
from app.core.remediation_optimizer import RemediationOptimizer
from app.core.risk_engine import RiskEngine
from src.facts.extractors.k8s_extractor import K8sFactExtractor
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
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder
from src.graph.builders.iam_policy_parser import parse_all_roles, parse_all_users
from src.graph.builders.k8s_graph_builder import K8sGraphBuilder
from src.graph.builders.unified_graph_builder import UnifiedGraphBuilder

logger = logging.getLogger(__name__)

REQUIRED_SCAN_TYPES = {SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE}
MAX_HOPS = 7
MAX_ATTACK_PATHS = 100


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
        self._k8s_extractor = K8sFactExtractor()
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
            
            # Step 2: Build domain graph results and merge through UnifiedGraphBuilder
            k8s_result = await asyncio.to_thread(
                self._build_k8s_result,
                k8s_scan,
                k8s_scan_id,
            )
            aws_scan_result = await asyncio.to_thread(
                self._coerce_aws_scan_result,
                aws_scan,
                aws_scan_id,
            )
            bridge_result = await asyncio.to_thread(
                self._bridge_builder.build,
                k8s_scan,
                aws_scan_result,
            )
            aws_result = await asyncio.to_thread(
                self._build_aws_result,
                aws_scan_result,
                bridge_result,
            )
            unified_result = self._unified_graph_builder.build(k8s_result, aws_result)

            logger.info(
                "Unified graph assembled from domain results",
                cluster_id=cluster_id,
                k8s_nodes=len(k8s_result.nodes),
                aws_nodes=len(aws_result.nodes),
                unified_nodes=len(unified_result.nodes),
                unified_edges=len(unified_result.edges),
            )

            # Step 3: Adapt unified graph for existing NetworkX consumers
            graph = await self._graph_builder.build_from_unified_result(unified_result)
            
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
                max_path_length=MAX_HOPS,
                max_paths=MAX_ATTACK_PATHS,
            )
            
            # Step 5: Calculate risk scores
            enriched_paths = []
            for path in paths:
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
            
            # Sort by risk score
            enriched_paths.sort(key=lambda x: x["raw_final_risk"], reverse=True)
            graph_id = str(
                unified_result.metadata.get("k8s", {}).get("graph_id")
                or k8s_result.metadata.get("graph_id")
                or f"{k8s_scan_id}-graph"
            )
            await self._jobs.persist_attack_paths(
                cluster_id=cluster_id,
                graph_id=graph_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                attack_paths=enriched_paths,
            )
            remediation_optimization = self._remediation_optimizer.optimize(enriched_paths, graph)
            
            result = {
                "cluster_id": cluster_id,
                "scan_ids": {
                    "k8s": k8s_scan_id,
                    "aws": aws_scan_id,
                    "image": image_scan_id,
                },
                "stats": {
                    "facts": {
                        "total": len(k8s_result.edges) + len(aws_result.edges),
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
                        "total": len(paths),
                        "returned": len(enriched_paths),
                    },
                },
                "attack_paths": enriched_paths,
                "remediation_optimization": remediation_optimization,
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

    def _build_k8s_result(self, k8s_scan: Dict[str, Any], scan_id: str):
        k8s_facts = self._k8s_extractor.extract(k8s_scan)
        lateral_facts = self._lateral_extractor.extract(k8s_scan)
        return K8sGraphBuilder().build(
            [*k8s_facts, *lateral_facts],
            k8s_scan,
            scan_id=scan_id,
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

    def _coerce_aws_scan_result(self, aws_scan: Dict[str, Any] | AWSScanResult, scan_id: str) -> AWSScanResult:
        if isinstance(aws_scan, AWSScanResult):
            return aws_scan

        return AWSScanResult(
            scan_id=aws_scan.get("scan_id", scan_id),
            aws_account_id=aws_scan.get("aws_account_id", ""),
            scanned_at=aws_scan.get("scanned_at", ""),
            iam_roles=[
                role if isinstance(role, IAMRoleScan) else IAMRoleScan(**role)
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
