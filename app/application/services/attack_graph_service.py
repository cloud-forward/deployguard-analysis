from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schemas import (
    AttackGraphEdgeResponse,
    AttackGraphEdgeType,
    AttackGraphNodeResponse,
    AttackGraphNodeType,
    AttackGraphPathResponse,
    AttackGraphResponse,
    AttackGraphSeverity,
)

SEVERITY_ORDER = {severity.value: idx for idx, severity in enumerate(AttackGraphSeverity)}
NODE_TYPE_ALIASES = {
    "sa": AttackGraphNodeType.service_account,
    "serviceaccount": AttackGraphNodeType.service_account,
    "node_cred": AttackGraphNodeType.node_credential,
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
    AttackGraphNodeType.node_credential: "Node Credential",
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
            return dict(row)

        result = await self._db.execute(query_any, {"cluster_id": cluster_id})
        row = result.mappings().first()
        return dict(row) if row else None

    async def _get_table_columns(self, table_name: str) -> set[str]:
        conn = await self._db.connection()

        def _inspect_columns(sync_conn):
            inspector = inspect(sync_conn)
            if not inspector.has_table(table_name):
                return set()
            return {column["name"] for column in inspector.get_columns(table_name)}

        return await conn.run_sync(_inspect_columns)

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

        id_col = self._pick_column(columns, "edge_id", "id")
        source_col = self._pick_column(columns, "source", "source_node_id")
        target_col = self._pick_column(columns, "target", "target_node_id")
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

        title_col = self._pick_column(columns, "title", "name")
        severity_col = self._pick_column(columns, "severity", "risk_level")
        node_ids_col = self._pick_column(columns, "node_ids", "path_nodes", "path_node_ids")
        edge_ids_col = self._pick_column(columns, "edge_ids", "path_edges", "path_edge_ids")

        select_parts = [
            f"{id_col} AS id",
            f"{title_col} AS title" if title_col else "NULL AS title",
            f"{severity_col} AS severity" if severity_col else "NULL AS severity",
            f"{node_ids_col} AS node_ids" if node_ids_col else "NULL AS node_ids",
            f"{edge_ids_col} AS edge_ids" if edge_ids_col else "NULL AS edge_ids",
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

        paths: list[AttackGraphPathResponse] = []
        for row in result.mappings().all():
            node_ids = self._normalize_string_list(row.get("node_ids"))
            if not node_ids or any(node_id not in valid_node_ids for node_id in node_ids):
                continue

            edge_ids = self._normalize_string_list(row.get("edge_ids"))
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
