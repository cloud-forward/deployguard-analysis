from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import bindparam, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schemas import (
    AttackPathDetailEnvelopeResponse,
    AttackPathDetailResponse,
    AttackPathEdgeSequenceResponse,
    AttackPathListItemResponse,
    AttackPathListResponse,
    AttackGraphEdgeResponse,
    AttackGraphEdgeType,
    AttackGraphNodeResponse,
    AttackGraphNodeType,
    AttackGraphPathResponse,
    AttackGraphResponse,
    AttackGraphSeverity,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationDetailResponse,
    RemediationRecommendationListItemResponse,
    RemediationRecommendationListResponse,
)

SEVERITY_ORDER = {severity.value: idx for idx, severity in enumerate(AttackGraphSeverity)}
NODE_TYPE_ALIASES = {
    "sa": AttackGraphNodeType.service_account,
    "serviceaccount": AttackGraphNodeType.service_account,
    "iam-role": AttackGraphNodeType.iam_role,
    "iam_role": AttackGraphNodeType.iam_role,
    "iam": AttackGraphNodeType.iam_role,
    "iam-user": AttackGraphNodeType.iam_user,
    "iam_user": AttackGraphNodeType.iam_user,
    "s3": AttackGraphNodeType.s3_bucket,
    "bucket": AttackGraphNodeType.s3_bucket,
    "securitygroup": AttackGraphNodeType.security_group,
    "security-group": AttackGraphNodeType.security_group,
    "sg": AttackGraphNodeType.security_group,
    "ec2": AttackGraphNodeType.ec2_instance,
}
logger = logging.getLogger(__name__)
EDGE_TYPE_ALIASES = {
    "pod_uses_service_account": AttackGraphEdgeType.uses,
    "uses_image": AttackGraphEdgeType.uses,
    "service_account_bound_role": AttackGraphEdgeType.bound_to,
    "service_account_bound_cluster_role": AttackGraphEdgeType.bound_to,
    "role_grants_resource": AttackGraphEdgeType.grants,
    "role_grants_pod_exec": AttackGraphEdgeType.grants,
    "escapes_to": AttackGraphEdgeType.escapes_to,
    "service_account_assumes_iam_role": AttackGraphEdgeType.assumes,
    "instance_profile_assumes": AttackGraphEdgeType.assumes,
    "iam_role_access_resource": AttackGraphEdgeType.accesses,
    "iam_user_access_resource": AttackGraphEdgeType.accesses,
    "pod_mounts_secret": AttackGraphEdgeType.accesses,
    "pod_uses_env_from_secret": AttackGraphEdgeType.accesses,
    "secret_contains_credentials": AttackGraphEdgeType.accesses,
    "secret_contains_aws_credentials": AttackGraphEdgeType.accesses,
    "ingress_exposes_service": AttackGraphEdgeType.allows,
    "security_group_allows": AttackGraphEdgeType.allows,
    "lateral_move": AttackGraphEdgeType.allows,
    "exposes_token": AttackGraphEdgeType.allows,
    "service_targets_pod": AttackGraphEdgeType.runs,
}
KIND_DISPLAY = {
    AttackGraphNodeType.pod: "Pod",
    AttackGraphNodeType.service_account: "Service Account",
    AttackGraphNodeType.role: "Role",
    AttackGraphNodeType.cluster_role: "Cluster Role",
    AttackGraphNodeType.secret: "Secret",
    AttackGraphNodeType.service: "Service",
    AttackGraphNodeType.ingress: "Ingress",
    AttackGraphNodeType.node: "Node",
    AttackGraphNodeType.container_image: "Container Image",
    AttackGraphNodeType.iam_role: "IAM Role",
    AttackGraphNodeType.iam_user: "IAM User",
    AttackGraphNodeType.s3_bucket: "S3 Bucket",
    AttackGraphNodeType.rds: "RDS",
    AttackGraphNodeType.security_group: "Security Group",
    AttackGraphNodeType.ec2_instance: "EC2 Instance",
    AttackGraphNodeType.unknown: "Unknown",
}


class AttackGraphService:
    def __init__(self, cluster_repository, db: AsyncSession) -> None:
        self._clusters = cluster_repository
        self._db = db

    async def get_attack_graph(self, cluster_id: str) -> AttackGraphResponse:
        cluster = await self._clusters.get_by_id(cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        analysis = await self._get_latest_analysis_context(cluster_id)
        if analysis is None:
            return AttackGraphResponse(cluster_id=cluster_id)

        graph_id = analysis.get("graph_id")
        if not graph_id:
            return AttackGraphResponse(
                cluster_id=cluster_id,
                analysis_run_id=analysis.get("analysis_run_id"),
                generated_at=analysis.get("generated_at"),
            )

        nodes = await self._get_nodes(str(graph_id))
        valid_node_ids = {node.id for node in nodes}
        edges = await self._get_edges(str(graph_id), valid_node_ids=valid_node_ids)
        valid_edge_ids = {edge.id for edge in edges}
        edge_ids_by_pair = {(edge.source, edge.target): edge.id for edge in edges}
        node_labels = {node.id: node.label for node in nodes}
        paths = await self._get_paths(
            str(graph_id),
            valid_node_ids=valid_node_ids,
            valid_edge_ids=valid_edge_ids,
            nodes_by_id={node.id: node for node in nodes},
            edges_by_id={edge.id: edge for edge in edges},
            node_labels=node_labels,
            edge_ids_by_pair=edge_ids_by_pair,
        )

        return AttackGraphResponse(
            cluster_id=cluster_id,
            analysis_run_id=analysis.get("analysis_run_id"),
            generated_at=analysis.get("generated_at"),
            nodes=nodes,
            edges=edges,
            paths=paths,
        )

    async def get_attack_paths(self, cluster_id: str) -> AttackPathListResponse:
        cluster = await self._clusters.get_by_id(cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        analysis = await self._get_latest_analysis_context(cluster_id)
        if analysis is None or not analysis.get("graph_id"):
            return AttackPathListResponse(
                cluster_id=cluster_id,
                analysis_run_id=analysis.get("analysis_run_id") if analysis else None,
                generated_at=analysis.get("generated_at") if analysis else None,
            )

        items = await self._get_attack_path_items(str(analysis["graph_id"]))
        return AttackPathListResponse(
            cluster_id=cluster_id,
            analysis_run_id=analysis.get("analysis_run_id"),
            generated_at=analysis.get("generated_at"),
            items=items,
        )

    async def get_attack_path_detail(self, cluster_id: str, path_id: str) -> AttackPathDetailEnvelopeResponse:
        cluster = await self._clusters.get_by_id(cluster_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        analysis = await self._get_latest_analysis_context(cluster_id)
        if analysis is None or not analysis.get("graph_id"):
            return AttackPathDetailEnvelopeResponse(
                cluster_id=cluster_id,
                analysis_run_id=analysis.get("analysis_run_id") if analysis else None,
                generated_at=analysis.get("generated_at") if analysis else None,
                path=None,
            )

        path = await self._get_attack_path_detail(str(analysis["graph_id"]), path_id)
        if path is None:
            raise HTTPException(status_code=404, detail="Attack path not found")

        return AttackPathDetailEnvelopeResponse(
            cluster_id=cluster_id,
            analysis_run_id=analysis.get("analysis_run_id"),
            generated_at=analysis.get("generated_at"),
            path=path,
        )

    async def get_remediation_recommendations(self, cluster_id: str) -> RemediationRecommendationListResponse:
        logger.info(
            "remediation_list_request",
            extra={"cluster_id": cluster_id, "service_method": "get_remediation_recommendations"},
        )
        try:
            cluster = await self._clusters.get_by_id(cluster_id)
            if cluster is None:
                logger.warning(
                    "remediation_context_resolved",
                    extra={
                        "cluster_id": cluster_id,
                        "service_method": "get_remediation_recommendations",
                        "cluster_found": False,
                    },
                )
                raise HTTPException(status_code=404, detail="Cluster not found")

            analysis = await self._get_latest_analysis_context(cluster_id)
            logger.info(
                "remediation_context_resolved",
                extra={
                    "cluster_id": cluster_id,
                    "service_method": "get_remediation_recommendations",
                    "analysis_run_id": analysis.get("analysis_run_id") if analysis else None,
                    "graph_id": str(analysis.get("graph_id")) if analysis and analysis.get("graph_id") else None,
                    "generated_at": analysis.get("generated_at") if analysis else None,
                },
            )
            if analysis is None or not analysis.get("graph_id"):
                logger.warning(
                    "remediation_rows_loaded",
                    extra={
                        "cluster_id": cluster_id,
                        "service_method": "get_remediation_recommendations",
                        "graph_id": str(analysis.get("graph_id")) if analysis and analysis.get("graph_id") else None,
                        "recommendation_count": 0,
                        "empty_result": True,
                    },
                )
                return RemediationRecommendationListResponse(
                    cluster_id=cluster_id,
                    analysis_run_id=self._normalize_optional_str(analysis.get("analysis_run_id")) if analysis else None,
                    generated_at=analysis.get("generated_at") if analysis else None,
                )

            graph_id = str(analysis["graph_id"])
            items = await self._get_remediation_recommendation_items(graph_id)
            logger.info(
                "remediation_rows_loaded",
                extra={
                    "cluster_id": cluster_id,
                    "service_method": "get_remediation_recommendations",
                    "graph_id": graph_id,
                    "recommendation_count": len(items),
                    "ordering_path": "recommendation_rank,cumulative_risk_reduction,recommendation_id",
                    "empty_result": len(items) == 0,
                },
            )
            return RemediationRecommendationListResponse(
                cluster_id=cluster_id,
                analysis_run_id=self._normalize_optional_str(analysis.get("analysis_run_id")),
                generated_at=analysis.get("generated_at"),
                items=items,
            )
        except Exception as exc:
            logger.exception(
                "remediation_list_request_failed",
                extra={
                    "cluster_id": cluster_id,
                    "service_method": "get_remediation_recommendations",
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            raise

    async def get_remediation_recommendation_detail(
        self,
        cluster_id: str,
        recommendation_id: str,
    ) -> RemediationRecommendationDetailEnvelopeResponse:
        logger.info(
            "remediation_detail_request",
            extra={
                "cluster_id": cluster_id,
                "recommendation_id": recommendation_id,
                "service_method": "get_remediation_recommendation_detail",
            },
        )
        try:
            cluster = await self._clusters.get_by_id(cluster_id)
            if cluster is None:
                logger.warning(
                    "remediation_context_resolved",
                    extra={
                        "cluster_id": cluster_id,
                        "recommendation_id": recommendation_id,
                        "service_method": "get_remediation_recommendation_detail",
                        "cluster_found": False,
                    },
                )
                raise HTTPException(status_code=404, detail="Cluster not found")

            analysis = await self._get_latest_analysis_context(cluster_id)
            logger.info(
                "remediation_context_resolved",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation_id,
                    "service_method": "get_remediation_recommendation_detail",
                    "analysis_run_id": analysis.get("analysis_run_id") if analysis else None,
                    "graph_id": str(analysis.get("graph_id")) if analysis and analysis.get("graph_id") else None,
                    "generated_at": analysis.get("generated_at") if analysis else None,
                },
            )
            if analysis is None or not analysis.get("graph_id"):
                logger.warning(
                    "remediation_rows_loaded",
                    extra={
                        "cluster_id": cluster_id,
                        "recommendation_id": recommendation_id,
                        "service_method": "get_remediation_recommendation_detail",
                        "graph_id": str(analysis.get("graph_id")) if analysis and analysis.get("graph_id") else None,
                        "recommendation_found": False,
                        "empty_result": True,
                    },
                )
                return RemediationRecommendationDetailEnvelopeResponse(
                    cluster_id=cluster_id,
                    analysis_run_id=self._normalize_optional_str(analysis.get("analysis_run_id")) if analysis else None,
                    generated_at=analysis.get("generated_at") if analysis else None,
                    recommendation=None,
                )

            graph_id = str(analysis["graph_id"])
            recommendation = await self._get_remediation_recommendation_detail(graph_id, recommendation_id)
            logger.info(
                "remediation_rows_loaded",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation_id,
                    "service_method": "get_remediation_recommendation_detail",
                    "graph_id": graph_id,
                    "recommendation_found": recommendation is not None,
                },
            )
            if recommendation is None:
                raise HTTPException(status_code=404, detail="Remediation recommendation not found")

            return RemediationRecommendationDetailEnvelopeResponse(
                cluster_id=cluster_id,
                analysis_run_id=self._normalize_optional_str(analysis.get("analysis_run_id")),
                generated_at=analysis.get("generated_at"),
                recommendation=recommendation,
            )
        except Exception as exc:
            logger.exception(
                "remediation_detail_request_failed",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation_id,
                    "service_method": "get_remediation_recommendation_detail",
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            raise

    async def _get_latest_analysis_context(self, cluster_id: str) -> Optional[dict[str, Any]]:
        query_with_graph = text(
            """
            SELECT id AS analysis_run_id,
                   graph_id AS graph_id,
                   COALESCE(completed_at, created_at) AS generated_at
            FROM analysis_jobs
            WHERE cluster_id = :cluster_id AND graph_id IS NOT NULL
            ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC
            LIMIT 1
            """
        )
        query_any = text(
            """
            SELECT id AS analysis_run_id,
                   graph_id AS graph_id,
                   COALESCE(completed_at, created_at) AS generated_at
            FROM analysis_jobs
            WHERE cluster_id = :cluster_id
            ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC
            LIMIT 1
            """
        )

        result = await self._db.execute(query_with_graph, {"cluster_id": cluster_id})
        row = result.mappings().first()
        if row:
            logger.debug(
                "remediation_context_resolved",
                extra={
                    "cluster_id": cluster_id,
                    "context_query": "analysis_with_graph",
                    "analysis_run_id": row.get("analysis_run_id"),
                    "graph_id": str(row.get("graph_id")) if row.get("graph_id") else None,
                },
            )
            return dict(row)

        result = await self._db.execute(query_any, {"cluster_id": cluster_id})
        row = result.mappings().first()
        logger.debug(
            "remediation_context_resolved",
            extra={
                "cluster_id": cluster_id,
                "context_query": "analysis_any",
                "analysis_run_id": row.get("analysis_run_id") if row else None,
                "graph_id": str(row.get("graph_id")) if row and row.get("graph_id") else None,
            },
        )
        return dict(row) if row else None

    async def _get_table_columns(self, table_name: str) -> set[str]:
        conn = await self._db.connection()

        def _inspect_columns(sync_conn):
            inspector = inspect(sync_conn)
            if not inspector.has_table(table_name):
                return set()
            return {column["name"] for column in inspector.get_columns(table_name)}

        return await conn.run_sync(_inspect_columns)

    async def _get_attack_path_items(self, graph_id: str) -> list[AttackPathListItemResponse]:
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

        result = await self._db.execute(
            text(
                f"""
                SELECT {", ".join(select_parts)}
                FROM attack_paths
                WHERE graph_id = :graph_id
                """
            ),
            {"graph_id": graph_id},
        )

        items = [
            AttackPathListItemResponse(
                path_id=str(row["path_id"]),
                title=self._normalize_path_title(row.get("title"), row.get("path_id"), self._normalize_string_list(row.get("node_ids")), {}),
                risk_level=self._normalize_severity(row.get("risk_level")),
                risk_score=self._normalize_float(row.get("risk_score")),
                raw_final_risk=self._normalize_float(row.get("raw_final_risk")),
                hop_count=self._normalize_int(row.get("hop_count")) or max(len(self._normalize_string_list(row.get("node_ids"))) - 1, 0),
                entry_node_id=self._normalize_optional_str(row.get("entry_node_id")),
                target_node_id=self._normalize_optional_str(row.get("target_node_id")),
                node_ids=self._normalize_string_list(row.get("node_ids")),
            )
            for row in result.mappings().all()
        ]

        return sorted(
            items,
            key=lambda item: (
                SEVERITY_ORDER.get(item.risk_level, 99),
                -(item.raw_final_risk or -1.0),
                item.hop_count,
                item.path_id,
            ),
        )

    async def _get_attack_path_detail(self, graph_id: str, path_id: str) -> AttackPathDetailResponse | None:
        columns = await self._get_table_columns("attack_paths")
        if not columns:
            return None

        public_id_col = self._pick_column(columns, "path_id", "attack_path_id", "id")
        if not public_id_col:
            return None
        row_id_col = self._pick_column(columns, "id")

        title_col = self._pick_column(columns, "title", "name")
        severity_col = self._pick_column(columns, "severity", "risk_level")
        risk_score_col = self._pick_column(columns, "risk_score")
        raw_final_risk_col = self._pick_column(columns, "raw_final_risk")
        hop_count_col = self._pick_column(columns, "hop_count")
        entry_col = self._pick_column(columns, "entry_node_id")
        target_col = self._pick_column(columns, "target_node_id")
        node_ids_col = self._pick_column(columns, "node_ids", "path_nodes", "path_node_ids")

        select_parts = [
            f"{public_id_col} AS path_id",
            f"{row_id_col} AS persisted_path_id" if row_id_col else f"{public_id_col} AS persisted_path_id",
            f"{title_col} AS title" if title_col else "NULL AS title",
            f"{severity_col} AS risk_level" if severity_col else "NULL AS risk_level",
            f"{risk_score_col} AS risk_score" if risk_score_col else "NULL AS risk_score",
            f"{raw_final_risk_col} AS raw_final_risk" if raw_final_risk_col else "NULL AS raw_final_risk",
            f"{hop_count_col} AS hop_count" if hop_count_col else "NULL AS hop_count",
            f"{entry_col} AS entry_node_id" if entry_col else "NULL AS entry_node_id",
            f"{target_col} AS target_node_id" if target_col else "NULL AS target_node_id",
            f"{node_ids_col} AS node_ids" if node_ids_col else "NULL AS node_ids",
        ]

        row = (
            await self._db.execute(
                text(
                    f"""
                    SELECT {", ".join(select_parts)}
                    FROM attack_paths
                    WHERE graph_id = :graph_id AND {public_id_col} = :path_id
                    LIMIT 1
                    """
                ),
                {"graph_id": graph_id, "path_id": path_id},
            )
        ).mappings().first()
        if row is None:
            return None

        node_ids = self._normalize_string_list(row.get("node_ids"))
        edges = await self._get_attack_path_edge_sequence(str(row.get("persisted_path_id")), [])
        edge_ids = await self._get_graph_edge_ids_for_path(graph_id, edges, node_ids)

        return AttackPathDetailResponse(
            path_id=str(row["path_id"]),
            title=self._normalize_path_title(row.get("title"), row.get("path_id"), node_ids, {}),
            risk_level=self._normalize_severity(row.get("risk_level")),
            risk_score=self._normalize_float(row.get("risk_score")),
            raw_final_risk=self._normalize_float(row.get("raw_final_risk")),
            hop_count=self._normalize_int(row.get("hop_count")) or max(len(node_ids) - 1, 0),
            entry_node_id=self._normalize_optional_str(row.get("entry_node_id")),
            target_node_id=self._normalize_optional_str(row.get("target_node_id")),
            node_ids=node_ids,
            edge_ids=edge_ids,
            edges=edges,
        )

    async def _get_attack_path_edge_sequence(
        self,
        persisted_path_id: str,
        fallback_edge_ids: list[str],
    ) -> list[AttackPathEdgeSequenceResponse]:
        columns = await self._get_table_columns("attack_path_edges")
        if not columns:
            return []

        edge_id_col = self._pick_column(columns, "id")
        source_col = self._pick_column(columns, "source_node_id", "source")
        target_col = self._pick_column(columns, "target_node_id", "target")
        type_col = self._pick_column(columns, "edge_type", "type")
        if not edge_id_col or not source_col or not target_col or not type_col:
            return []

        index_col = self._pick_column(columns, "edge_index", "path_edge_index", "sequence")
        metadata_col = self._pick_column(columns, "metadata", "properties", "attributes")

        select_parts = [
            f"{edge_id_col} AS edge_id",
            f"{index_col} AS edge_index" if index_col else "NULL AS edge_index",
            f"{source_col} AS source_node_id",
            f"{target_col} AS target_node_id",
            f"{type_col} AS edge_type",
            f"{metadata_col} AS metadata" if metadata_col else "NULL AS metadata",
        ]

        result = await self._db.execute(
            text(
                f"""
                SELECT {", ".join(select_parts)}
                FROM attack_path_edges
                WHERE path_id = :path_id
                """
            ),
            {"path_id": persisted_path_id},
        )

        edges = [
            AttackPathEdgeSequenceResponse(
                edge_id=str(row["edge_id"]),
                edge_index=self._normalize_int(row.get("edge_index")) or 0,
                source_node_id=str(row["source_node_id"]),
                target_node_id=str(row["target_node_id"]),
                edge_type=str(row["edge_type"]),
                metadata=self._normalize_object(row.get("metadata")),
            )
            for row in result.mappings().all()
        ]
        if edges:
            return sorted(edges, key=lambda edge: (edge.edge_index, edge.edge_id))

        return [
            AttackPathEdgeSequenceResponse(
                edge_id=edge_id,
                edge_index=index,
                source_node_id="",
                target_node_id="",
                edge_type="unknown",
                metadata={},
            )
            for index, edge_id in enumerate(fallback_edge_ids)
        ]

    async def _get_remediation_recommendation_items(self, graph_id: str) -> list[RemediationRecommendationListItemResponse]:
        try:
            columns = await self._get_table_columns("remediation_recommendations")
        except Exception as exc:
            if self._is_missing_table_error(exc, "remediation_recommendations"):
                logger.warning(
                    "remediation_rows_loaded",
                    extra={
                        "graph_id": graph_id,
                        "stage": "_get_remediation_recommendation_items",
                        "table_name": "remediation_recommendations",
                        "recommendation_count": 0,
                        "empty_result": True,
                        "missing_table_or_columns": True,
                    },
                )
                return []
            raise
        if not columns:
            logger.warning(
                "remediation_rows_loaded",
                extra={
                    "graph_id": graph_id,
                    "stage": "_get_remediation_recommendation_items",
                    "table_name": "remediation_recommendations",
                    "recommendation_count": 0,
                    "empty_result": True,
                    "missing_table_or_columns": True,
                },
            )
            return []

        id_col = self._pick_column(columns, "recommendation_id", "id")
        rank_col = self._pick_column(columns, "recommendation_rank", "rank", "position")
        if not id_col or not rank_col:
            logger.warning(
                "remediation_rows_loaded",
                extra={
                    "graph_id": graph_id,
                    "stage": "_get_remediation_recommendation_items",
                    "table_name": "remediation_recommendations",
                    "recommendation_count": 0,
                    "empty_result": True,
                    "ordering_path": "unresolved",
                    "missing_required_columns": True,
                },
            )
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

        try:
            result = await self._db.execute(
                text(
                    f"""
                    SELECT {", ".join(select_parts)}
                    FROM remediation_recommendations
                    WHERE graph_id = :graph_id
                    """
                ),
                {"graph_id": graph_id},
            )
        except Exception as exc:
            if self._is_missing_table_error(exc, "remediation_recommendations"):
                logger.warning(
                    "remediation_rows_loaded",
                    extra={
                        "graph_id": graph_id,
                        "stage": "_get_remediation_recommendation_items",
                        "table_name": "remediation_recommendations",
                        "recommendation_count": 0,
                        "empty_result": True,
                        "missing_table_or_columns": True,
                    },
                )
                return []
            raise
        rows = result.mappings().all()
        logger.info(
            "remediation_rows_loaded",
            extra={
                "graph_id": graph_id,
                "stage": "_get_remediation_recommendation_items",
                "raw_row_count": len(rows),
                "ordering_path": "recommendation_rank,cumulative_risk_reduction,recommendation_id",
            },
        )
        try:
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
        except Exception as exc:
            logger.exception(
                "remediation_serialization_failed",
                extra={
                    "graph_id": graph_id,
                    "stage": "_get_remediation_recommendation_items",
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            raise

        return sorted(
            items,
            key=lambda item: (
                item.recommendation_rank,
                -(item.cumulative_risk_reduction or -1.0),
                item.recommendation_id,
            ),
        )

    @staticmethod
    def _is_missing_table_error(exc: Exception, table_name: str) -> bool:
        message = str(exc).lower()
        normalized_table = table_name.lower()
        return normalized_table in message and any(
            marker in message
            for marker in ("no such table", "does not exist", "undefined table")
        )

    async def _get_remediation_recommendation_detail(
        self,
        graph_id: str,
        recommendation_id: str,
    ) -> RemediationRecommendationDetailResponse | None:
        columns = await self._get_table_columns("remediation_recommendations")
        if not columns:
            logger.warning(
                "remediation_rows_loaded",
                extra={
                    "graph_id": graph_id,
                    "recommendation_id": recommendation_id,
                    "stage": "_get_remediation_recommendation_detail",
                    "table_name": "remediation_recommendations",
                    "recommendation_found": False,
                    "missing_table_or_columns": True,
                },
            )
            return None

        id_col = self._pick_column(columns, "recommendation_id", "id")
        rank_col = self._pick_column(columns, "recommendation_rank", "rank", "position")
        if not id_col or not rank_col:
            logger.warning(
                "remediation_rows_loaded",
                extra={
                    "graph_id": graph_id,
                    "recommendation_id": recommendation_id,
                    "stage": "_get_remediation_recommendation_detail",
                    "table_name": "remediation_recommendations",
                    "recommendation_found": False,
                    "missing_required_columns": True,
                },
            )
            return None

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

        row = (
            await self._db.execute(
                text(
                    f"""
                    SELECT {", ".join(select_parts)}
                    FROM remediation_recommendations
                    WHERE graph_id = :graph_id AND {id_col} = :recommendation_id
                    LIMIT 1
                    """
                ),
                {"graph_id": graph_id, "recommendation_id": recommendation_id},
            )
        ).mappings().first()
        if row is None:
            logger.warning(
                "remediation_rows_loaded",
                extra={
                    "graph_id": graph_id,
                    "recommendation_id": recommendation_id,
                    "stage": "_get_remediation_recommendation_detail",
                    "recommendation_found": False,
                },
            )
            return None
        logger.info(
            "remediation_rows_loaded",
            extra={
                "graph_id": graph_id,
                "recommendation_id": recommendation_id,
                "stage": "_get_remediation_recommendation_detail",
                "recommendation_found": True,
            },
        )
        try:
            return RemediationRecommendationDetailResponse(
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
        except Exception as exc:
            logger.exception(
                "remediation_serialization_failed",
                extra={
                    "graph_id": graph_id,
                    "recommendation_id": recommendation_id,
                    "stage": "_get_remediation_recommendation_detail",
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            raise

    async def _get_nodes(self, graph_id: str) -> list[AttackGraphNodeResponse]:
        columns = await self._get_table_columns("graph_nodes")
        if not columns:
            return []

        id_col = self._pick_column(columns, "node_id", "id")
        type_col = self._pick_column(columns, "node_type", "type")
        if not id_col or not type_col:
            return []

        label_col = self._pick_column(columns, "label", "display_name", "name")
        severity_col = self._pick_column(columns, "severity", "risk_level")
        risk_col = self._pick_column(columns, "base_risk", "risk_score")
        runtime_col = self._pick_column(columns, "has_runtime_evidence", "runtime_evidence")
        entry_col = self._pick_column(columns, "is_entry_point")
        crown_col = self._pick_column(columns, "is_crown_jewel")
        metadata_col = self._pick_column(columns, "metadata", "properties", "attributes")

        select_parts = [
            f"{id_col} AS id",
            f"{type_col} AS type",
            f"{label_col} AS label" if label_col else "NULL AS label",
            f"{severity_col} AS severity" if severity_col else "NULL AS severity",
            f"{risk_col} AS base_risk" if risk_col else "NULL AS base_risk",
            f"{runtime_col} AS has_runtime_evidence" if runtime_col else "NULL AS has_runtime_evidence",
            f"{entry_col} AS is_entry_point" if entry_col else "NULL AS is_entry_point",
            f"{crown_col} AS is_crown_jewel" if crown_col else "NULL AS is_crown_jewel",
            f"{metadata_col} AS metadata" if metadata_col else "NULL AS metadata",
        ]

        query = text(
            f"""
            SELECT {", ".join(select_parts)}
            FROM graph_nodes
            WHERE graph_id = :graph_id
            ORDER BY {id_col}
            """
        )
        result = await self._db.execute(query, {"graph_id": graph_id})

        nodes: list[AttackGraphNodeResponse] = []
        for row in result.mappings().all():
            node_id = str(row["id"])
            node_type = self._normalize_node_type(row.get("type"), node_id)
            nodes.append(
                AttackGraphNodeResponse(
                    id=node_id,
                    type=node_type,
                    label=self._normalize_label(row.get("label"), node_id),
                    severity=self._normalize_severity(row.get("severity"), row.get("base_risk")),
                    has_runtime_evidence=self._normalize_bool(row.get("has_runtime_evidence")),
                    is_entry_point=self._normalize_bool(row.get("is_entry_point")),
                    is_crown_jewel=self._normalize_bool(row.get("is_crown_jewel")),
                    metadata=self._enrich_node_metadata(self._normalize_object(row.get("metadata")), node_type),
                )
            )
        return nodes

    async def _get_edges(self, graph_id: str, *, valid_node_ids: set[str]) -> list[AttackGraphEdgeResponse]:
        columns = await self._get_table_columns("graph_edges")
        if not columns:
            return []

        id_col = self._pick_column(columns, "id")
        source_col = self._pick_column(columns, "source_node_id", "source")
        target_col = self._pick_column(columns, "target_node_id", "target")
        if not id_col or not source_col or not target_col:
            return []

        type_col = self._pick_column(columns, "type", "edge_type")
        metadata_col = self._pick_column(columns, "metadata", "properties", "attributes")

        select_parts = [
            f"{id_col} AS id",
            f"{source_col} AS source",
            f"{target_col} AS target",
            f"{type_col} AS type" if type_col else "NULL AS type",
            f"{metadata_col} AS metadata" if metadata_col else "NULL AS metadata",
        ]

        query = text(
            f"""
            SELECT {", ".join(select_parts)}
            FROM graph_edges
            WHERE graph_id = :graph_id
            ORDER BY {id_col}
            """
        )
        result = await self._db.execute(query, {"graph_id": graph_id})

        edges: list[AttackGraphEdgeResponse] = []
        for row in result.mappings().all():
            source = str(row["source"])
            target = str(row["target"])
            if source not in valid_node_ids or target not in valid_node_ids:
                continue
            edge_type = self._normalize_edge_type(row.get("type"))

            edges.append(
                AttackGraphEdgeResponse(
                    id=str(row["id"]),
                    source=source,
                    target=target,
                    type=edge_type,
                    metadata=self._enrich_edge_metadata(
                        self._normalize_object(row.get("metadata")),
                        raw_type=row.get("type"),
                        edge_type=edge_type,
                    ),
                )
            )
        return edges

    async def _get_paths(
        self,
        graph_id: str,
        *,
        valid_node_ids: set[str],
        valid_edge_ids: set[str],
        nodes_by_id: dict[str, AttackGraphNodeResponse],
        edges_by_id: dict[str, AttackGraphEdgeResponse],
        node_labels: dict[str, str],
        edge_ids_by_pair: dict[tuple[str, str], str],
    ) -> list[AttackGraphPathResponse]:
        columns = await self._get_table_columns("attack_paths")
        if not columns:
            return []

        id_col = self._pick_column(columns, "path_id", "attack_path_id", "id")
        if not id_col:
            return []
        row_id_col = self._pick_column(columns, "id")

        title_col = self._pick_column(columns, "title", "name")
        severity_col = self._pick_column(columns, "severity", "risk_level")
        node_ids_col = self._pick_column(columns, "node_ids", "path_nodes", "path_node_ids")

        select_parts = [
            f"{id_col} AS id",
            f"{row_id_col} AS persisted_path_id" if row_id_col else "NULL AS persisted_path_id",
            f"{title_col} AS title" if title_col else "NULL AS title",
            f"{severity_col} AS severity" if severity_col else "NULL AS severity",
            f"{node_ids_col} AS node_ids" if node_ids_col else "NULL AS node_ids",
        ]

        query = text(
            f"""
            SELECT {", ".join(select_parts)}
            FROM attack_paths
            WHERE graph_id = :graph_id
            ORDER BY {id_col}
            """
        )
        result = await self._db.execute(query, {"graph_id": graph_id})
        rows = result.mappings().all()
        persisted_path_ids = [
            str(row["persisted_path_id"])
            for row in rows
            if row.get("persisted_path_id") is not None
        ]
        edge_pairs_by_path_id = await self._get_attack_path_edge_pairs_by_path_ids(persisted_path_ids)

        paths: list[AttackGraphPathResponse] = []
        for row in rows:
            node_ids = self._normalize_string_list(row.get("node_ids"))
            if not node_ids or any(node_id not in valid_node_ids for node_id in node_ids):
                continue

            persisted_path_id = self._normalize_optional_str(row.get("persisted_path_id"))
            edge_ids = self._edge_ids_from_pairs(
                edge_pairs_by_path_id.get(persisted_path_id or "", []),
                edge_ids_by_pair,
            )
            if not edge_ids and node_ids:
                edge_ids = self._derive_edge_ids(node_ids, edge_ids_by_pair)
            if len(node_ids) > 1 and len(edge_ids) != len(node_ids) - 1:
                continue
            if any(edge_id not in valid_edge_ids for edge_id in edge_ids):
                continue

            title = self._normalize_path_title(row.get("title"), row.get("id"), node_ids, node_labels)
            paths.append(
                AttackGraphPathResponse(
                    id=str(row["id"]),
                    title=title,
                    summary=self._build_path_summary(title, node_ids, node_labels),
                    severity=self._normalize_severity(row.get("severity")),
                    evidence_count=self._count_path_evidence(node_ids, edge_ids, nodes_by_id, edges_by_id),
                    node_ids=node_ids,
                    edge_ids=edge_ids,
                )
            )

        return sorted(paths, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.title, item.id))

    async def _get_attack_path_edge_pairs_by_path_ids(
        self,
        path_ids: list[str],
    ) -> dict[str, list[tuple[str, str]]]:
        if not path_ids:
            return {}

        columns = await self._get_table_columns("attack_path_edges")
        if not columns:
            return {}

        path_id_col = self._pick_column(columns, "path_id")
        source_col = self._pick_column(columns, "source_node_id", "source")
        target_col = self._pick_column(columns, "target_node_id", "target")
        order_col = self._pick_column(columns, "sequence", "edge_index", "path_edge_index")
        if not path_id_col or not source_col or not target_col:
            return {}

        order_sql = order_col or path_id_col
        result = await self._db.execute(
            text(
                f"""
                SELECT {path_id_col} AS path_id, {source_col} AS source_node_id, {target_col} AS target_node_id
                FROM attack_path_edges
                WHERE {path_id_col} IN :path_ids
                ORDER BY {path_id_col}, {order_sql}
                """
            ).bindparams(bindparam("path_ids", expanding=True)),
            {"path_ids": path_ids},
        )

        pairs_by_path_id: dict[str, list[tuple[str, str]]] = {}
        for row in result.mappings().all():
            path_id = str(row["path_id"])
            pairs_by_path_id.setdefault(path_id, []).append(
                (str(row["source_node_id"]), str(row["target_node_id"]))
            )
        return pairs_by_path_id

    async def _get_graph_edge_ids_for_path(
        self,
        graph_id: str,
        edges: list[AttackPathEdgeSequenceResponse],
        node_ids: list[str],
    ) -> list[str]:
        edge_ids_by_pair = await self._get_graph_edge_ids_by_pair(graph_id)
        edge_ids = self._edge_ids_from_pairs(
            [(edge.source_node_id, edge.target_node_id) for edge in edges],
            edge_ids_by_pair,
        )
        if edge_ids:
            return edge_ids
        return self._derive_edge_ids(node_ids, edge_ids_by_pair)

    async def _get_graph_edge_ids_by_pair(self, graph_id: str) -> dict[tuple[str, str], str]:
        columns = await self._get_table_columns("graph_edges")
        if not columns:
            return {}

        id_col = self._pick_column(columns, "id")
        source_col = self._pick_column(columns, "source_node_id", "source")
        target_col = self._pick_column(columns, "target_node_id", "target")
        if not id_col or not source_col or not target_col:
            return {}

        result = await self._db.execute(
            text(
                f"""
                SELECT {id_col} AS id, {source_col} AS source_node_id, {target_col} AS target_node_id
                FROM graph_edges
                WHERE graph_id = :graph_id
                """
            ),
            {"graph_id": graph_id},
        )
        return {
            (str(row["source_node_id"]), str(row["target_node_id"])): str(row["id"])
            for row in result.mappings().all()
        }

    @staticmethod
    def _edge_ids_from_pairs(
        edge_pairs: list[tuple[str, str]],
        edge_ids_by_pair: dict[tuple[str, str], str],
    ) -> list[str]:
        edge_ids: list[str] = []
        for source, target in edge_pairs:
            edge_id = edge_ids_by_pair.get((source, target))
            if edge_id:
                edge_ids.append(edge_id)
        return edge_ids

    @staticmethod
    def _pick_column(columns: set[str], *candidates: str) -> Optional[str]:
        for candidate in candidates:
            if candidate in columns:
                return candidate
        return None

    @staticmethod
    def _normalize_bool(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"true", "t", "1", "yes", "y"}
        return False

    @staticmethod
    def _normalize_object(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            return parsed if isinstance(parsed, dict) else {}
        return {}

    @staticmethod
    def _normalize_string_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, tuple):
            return [str(item) for item in value]
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return [value] if value else []
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        return []

    @staticmethod
    def _normalize_float(value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_int(value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_optional_str(value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value)
        return normalized if normalized else None

    @staticmethod
    def _normalize_int_list(value: Any) -> list[int]:
        if value is None:
            return []
        if isinstance(value, list):
            candidates = value
        elif isinstance(value, tuple):
            candidates = list(value)
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
    def _normalize_label(value: Any, node_id: str) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        parts = [part for part in node_id.split(":") if part]
        tail = parts[-1] if parts else node_id
        return tail or node_id

    @staticmethod
    def _normalize_node_type(value: Any, node_id: str) -> AttackGraphNodeType:
        normalized = str(value or "").strip().lower().replace("-", "_")
        if normalized in AttackGraphNodeType._value2member_map_:
            return AttackGraphNodeType(normalized)
        if normalized in NODE_TYPE_ALIASES:
            return NODE_TYPE_ALIASES[normalized]

        prefix = node_id.split(":", 1)[0].strip().lower().replace("-", "_")
        if prefix in AttackGraphNodeType._value2member_map_:
            return AttackGraphNodeType(prefix)
        if prefix in NODE_TYPE_ALIASES:
            return NODE_TYPE_ALIASES[prefix]
        return AttackGraphNodeType.unknown

    @staticmethod
    def _enrich_node_metadata(metadata: dict[str, Any], node_type: AttackGraphNodeType) -> dict[str, Any]:
        enriched = dict(metadata)
        namespace = AttackGraphService._first_non_empty(metadata, "namespace", "ns")
        image = AttackGraphService._first_non_empty(metadata, "image", "image_name")
        service_account = AttackGraphService._first_non_empty(
            metadata, "service_account", "serviceAccount", "service_account_name", "sa_name"
        )
        account_id = AttackGraphService._first_non_empty(metadata, "account_id", "aws_account_id", "account")

        if namespace is not None:
            enriched["namespace"] = namespace
        if image is not None:
            enriched["image"] = image
        if service_account is not None:
            enriched["service_account"] = service_account
        if account_id is not None:
            enriched["account_id"] = account_id
        enriched.setdefault("kind_display", KIND_DISPLAY[node_type])
        return enriched

    @staticmethod
    def _enrich_edge_metadata(
        metadata: dict[str, Any],
        *,
        raw_type: Any,
        edge_type: AttackGraphEdgeType,
    ) -> dict[str, Any]:
        enriched = dict(metadata)
        reason = AttackGraphService._derive_edge_reason(raw_type, edge_type)
        if reason:
            enriched.setdefault("reason", reason)
        return enriched

    @staticmethod
    def _normalize_edge_type(value: Any) -> AttackGraphEdgeType:
        normalized = str(value or "").strip().lower()
        if normalized in AttackGraphEdgeType._value2member_map_:
            return AttackGraphEdgeType(normalized)
        if normalized in EDGE_TYPE_ALIASES:
            return EDGE_TYPE_ALIASES[normalized]
        if "bound" in normalized:
            return AttackGraphEdgeType.bound_to
        if "grant" in normalized:
            return AttackGraphEdgeType.grants
        if "escape" in normalized:
            return AttackGraphEdgeType.escapes_to
        if "assum" in normalized:
            return AttackGraphEdgeType.assumes
        if "access" in normalized:
            return AttackGraphEdgeType.accesses
        if "run" in normalized:
            return AttackGraphEdgeType.runs
        if "use" in normalized:
            return AttackGraphEdgeType.uses
        return AttackGraphEdgeType.allows

    @staticmethod
    def _normalize_severity(value: Any, base_risk: Any = None) -> AttackGraphSeverity:
        normalized = str(value or "").strip().lower()
        if normalized in AttackGraphSeverity._value2member_map_:
            return AttackGraphSeverity(normalized)
        if base_risk is None:
            return AttackGraphSeverity.none

        try:
            score = float(base_risk)
        except (TypeError, ValueError):
            return AttackGraphSeverity.none

        if score >= 0.9:
            return AttackGraphSeverity.critical
        if score >= 0.7:
            return AttackGraphSeverity.high
        if score >= 0.4:
            return AttackGraphSeverity.medium
        if score > 0:
            return AttackGraphSeverity.low
        return AttackGraphSeverity.none

    @staticmethod
    def _derive_edge_reason(raw_type: Any, edge_type: AttackGraphEdgeType) -> str:
        normalized = str(raw_type or "").strip().lower()
        specific_reasons = {
            "pod_uses_service_account": "The pod uses this service account.",
            "service_account_bound_role": "The service account is bound to this role.",
            "service_account_bound_cluster_role": "The service account is bound to this cluster role.",
            "service_account_assumes_iam_role": "The service account can assume this IAM role.",
            "ingress_exposes_service": "The ingress exposes this service.",
            "service_targets_pod": "The service routes traffic to this pod.",
            "pod_mounts_secret": "The pod mounts this secret.",
            "pod_uses_env_from_secret": "The pod reads environment values from this secret.",
            "uses_image": "The workload runs this container image.",
            "role_grants_resource": "The role grants access to this resource.",
            "role_grants_pod_exec": "The role grants pod exec access.",
            "security_group_allows": "The security group allows this traffic path.",
            "iam_role_access_resource": "The IAM role can access this resource.",
            "iam_user_access_resource": "The IAM user can access this resource.",
            "escapes_to": "A container escape path reaches this target.",
        }
        if normalized in specific_reasons:
            return specific_reasons[normalized]

        generic_reasons = {
            AttackGraphEdgeType.uses: "A usage relationship exists between these nodes.",
            AttackGraphEdgeType.bound_to: "A binding relationship exists between these nodes.",
            AttackGraphEdgeType.grants: "A grant relationship exists between these nodes.",
            AttackGraphEdgeType.escapes_to: "An escape path exists between these nodes.",
            AttackGraphEdgeType.assumes: "An assume-role style relationship exists between these nodes.",
            AttackGraphEdgeType.accesses: "An access relationship exists between these nodes.",
            AttackGraphEdgeType.allows: "A connectivity or permission relationship exists between these nodes.",
            AttackGraphEdgeType.runs: "A runtime or routing relationship exists between these nodes.",
        }
        return generic_reasons.get(edge_type, "")

    @staticmethod
    def _derive_edge_ids(node_ids: list[str], edge_ids_by_pair: dict[tuple[str, str], str]) -> list[str]:
        derived: list[str] = []
        for source, target in zip(node_ids, node_ids[1:]):
            edge_id = edge_ids_by_pair.get((source, target))
            if edge_id:
                derived.append(edge_id)
        return derived

    @staticmethod
    def _normalize_path_title(
        value: Any,
        path_id: Any,
        node_ids: list[str],
        node_labels: dict[str, str],
    ) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if node_ids:
            start = node_labels.get(node_ids[0], node_ids[0])
            end = node_labels.get(node_ids[-1], node_ids[-1])
            return f"{start} -> {end}"
        return f"Path {path_id}"

    @staticmethod
    def _build_path_summary(title: str, node_ids: list[str], node_labels: dict[str, str]) -> str:
        if len(node_ids) < 2:
            return title or ""
        start = node_labels.get(node_ids[0], node_ids[0])
        end = node_labels.get(node_ids[-1], node_ids[-1])
        hop_count = len(node_ids) - 1
        return f"{start} to {end} in {hop_count} hop{'s' if hop_count != 1 else ''}"

    @staticmethod
    def _count_path_evidence(
        node_ids: list[str],
        edge_ids: list[str],
        nodes_by_id: dict[str, AttackGraphNodeResponse],
        edges_by_id: dict[str, AttackGraphEdgeResponse],
    ) -> int:
        count = 0
        count += sum(1 for node_id in node_ids if nodes_by_id.get(node_id) and nodes_by_id[node_id].has_runtime_evidence)
        count += sum(
            1
            for edge_id in edge_ids
            if edges_by_id.get(edge_id) and AttackGraphService._edge_has_runtime_evidence(edges_by_id[edge_id].metadata)
        )
        return count

    @staticmethod
    def _edge_has_runtime_evidence(metadata: dict[str, Any]) -> bool:
        return any(
            AttackGraphService._normalize_bool(metadata.get(key))
            for key in ("has_runtime_evidence", "runtime_evidence")
        )

    @staticmethod
    def _first_non_empty(metadata: dict[str, Any], *keys: str) -> Optional[str]:
        for key in keys:
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None
