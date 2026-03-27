"""
SQLAlchemy implementation of AnalysisJobRepository.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5
from sqlalchemy import MetaData, Table, delete, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.gateway.models import (
    AnalysisJob,
    AttackPath,
    AttackPathEdge,
    GraphSnapshot,
    RemediationRecommendation,
)
from src.facts.canonical_fact import Fact

logger = logging.getLogger(__name__)


class SqlAlchemyAnalysisJobRepository(AnalysisJobRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create_job(self, target_id: str, params: Dict[str, Any]) -> str:
        return "job_stub"

    async def mark_started(self, job_id: str) -> None:
        await self.mark_running(job_id)

    async def mark_completed(self, job_id: str, summary: Dict[str, Any]) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "completed"
        job.current_step = None
        job.error_message = None
        job.completed_at = datetime.utcnow()
        await self._session.commit()

    async def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def mark_running(self, job_id: str, current_step: str | None = None) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "running"
        job.current_step = current_step
        job.error_message = None
        if job.started_at is None:
            job.started_at = datetime.utcnow()
        await self._session.commit()

    async def update_current_step(self, job_id: str, current_step: str) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "running"
        job.current_step = current_step
        await self._session.commit()

    async def mark_failed(self, job_id: str, error_message: str) -> None:
        job = await self._session.get(AnalysisJob, job_id)
        if job is None:
            return None
        job.status = "failed"
        job.current_step = None
        job.error_message = error_message
        job.completed_at = datetime.utcnow()
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def get_analysis_job(self, job_id: str, user_id: str | None = None) -> AnalysisJob | None:
        query = select(AnalysisJob).where(AnalysisJob.id == job_id)
        if user_id is not None:
            query = query.where(AnalysisJob.user_id == user_id)
        return await self._session.scalar(query.limit(1))

    async def list_analysis_jobs(
        self,
        cluster_id: str | UUID,
        user_id: str,
        status: str | None = None,
    ) -> list[AnalysisJob]:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        query = (
            select(AnalysisJob)
            .where(
                AnalysisJob.cluster_id == normalized_cluster_id,
                AnalysisJob.user_id == user_id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
        )
        if status is not None:
            query = query.where(AnalysisJob.status == status)
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def create_analysis_job(
        self,
        cluster_id: str | UUID,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        expected_scans: list[str],
        user_id: str | None = None,
    ) -> str:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        job = AnalysisJob(
            cluster_id=normalized_cluster_id,
            user_id=user_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
            expected_scans=list(expected_scans),
            status="pending",
        )
        self._session.add(job)
        await self._session.commit()
        await self._session.refresh(job)
        return job.id

    async def persist_attack_paths(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str | None,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        attack_paths: list[Dict[str, Any]],
    ) -> str:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        attack_path_columns = await self._get_table_columns("attack_paths")
        attack_path_node_columns = await self._get_table_columns("attack_path_nodes")
        persisted_graph_id = await self._ensure_graph_snapshot(
            graph_id=graph_id,
            cluster_id=normalized_cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )

        path_ids_subquery = select(AttackPath.id).where(AttackPath.graph_id == persisted_graph_id)
        attack_path_nodes_fk_column = self._attack_path_nodes_fk_column(attack_path_node_columns)
        attack_path_nodes_table = (
            await self._reflect_table("attack_path_nodes")
            if attack_path_nodes_fk_column is not None
            else None
        )
        if attack_path_nodes_table is not None:
            await self._session.execute(
                attack_path_nodes_table.delete().where(
                    attack_path_nodes_table.c[attack_path_nodes_fk_column].in_(path_ids_subquery)
                )
            )
        await self._session.execute(delete(AttackPathEdge).where(AttackPathEdge.path_id.in_(path_ids_subquery)))
        await self._session.execute(delete(AttackPath).where(AttackPath.graph_id == persisted_graph_id))

        matching_job = await self._session.scalar(
            select(AnalysisJob)
            .where(
                AnalysisJob.cluster_id == normalized_cluster_id,
                AnalysisJob.k8s_scan_id == k8s_scan_id,
                AnalysisJob.aws_scan_id == aws_scan_id,
                AnalysisJob.image_scan_id == image_scan_id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
        )
        if matching_job is not None:
            matching_job.graph_id = persisted_graph_id

        for path in attack_paths:
            path_id = str(path["path_id"])
            node_ids = [str(node_id) for node_id in path.get("path", [])]
            if not self._is_persistable_attack_path(node_ids):
                continue
            edges = list(path.get("edges", []))
            persisted_path_row_id = self._attack_path_row_id(path_id)

            await self._bulk_insert_rows(
                "attack_paths",
                [
                    self._attack_path_row(
                        attack_path_columns=attack_path_columns,
                        graph_id=persisted_graph_id,
                        persisted_path_row_id=persisted_path_row_id,
                        path_id=path_id,
                        node_ids=node_ids,
                        path=path,
                    )
                ],
            )
            await self._bulk_insert_rows(
                "attack_path_nodes",
                [
                    self._attack_path_node_row(
                        attack_path_node_columns=attack_path_node_columns,
                        graph_id=persisted_graph_id,
                        persisted_path_row_id=persisted_path_row_id,
                        node_id=node_id,
                        position=position,
                    )
                    for position, node_id in enumerate(node_ids)
                ],
            )

            for index, edge in enumerate(edges):
                self._session.add(
                    AttackPathEdge(
                        id=self._path_edge_row_id(path_id, index),
                        path_id=persisted_path_row_id,
                        sequence=index,
                        source_node_id=str(edge.get("source", "")),
                        target_node_id=str(edge.get("target", "")),
                        edge_type=str(edge.get("type", "")),
                    )
                )

        await self._session.commit()
        return persisted_graph_id

    async def persist_remediation_recommendations(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str | None,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        remediation_optimization: Dict[str, Any],
    ) -> None:
        normalized_cluster_id = str(UUID(str(cluster_id)))
        persisted_graph_id = await self._ensure_graph_snapshot(
            graph_id=graph_id,
            cluster_id=normalized_cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )

        matching_job = await self._session.scalar(
            select(AnalysisJob)
            .where(
                AnalysisJob.cluster_id == normalized_cluster_id,
                AnalysisJob.k8s_scan_id == k8s_scan_id,
                AnalysisJob.aws_scan_id == aws_scan_id,
                AnalysisJob.image_scan_id == image_scan_id,
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
        )
        if matching_job is not None:
            matching_job.graph_id = persisted_graph_id

        await self._session.execute(
            delete(RemediationRecommendation).where(RemediationRecommendation.graph_id == persisted_graph_id)
        )

        recommendations = list(remediation_optimization.get("recommendations", []))
        for rank, recommendation in enumerate(recommendations):
            self._session.add(
                RemediationRecommendation(
                    graph_id=persisted_graph_id,
                    recommendation_id=str(recommendation.get("id", f"recommendation:{rank}")),
                    recommendation_rank=rank,
                    edge_source=self._as_str(recommendation.get("edge_source")),
                    edge_target=self._as_str(recommendation.get("edge_target")),
                    edge_type=self._as_str(recommendation.get("edge_type")),
                    fix_type=self._as_str(recommendation.get("fix_type")),
                    fix_description=self._as_str(recommendation.get("fix_description")),
                    blocked_path_ids=self._as_str_list(recommendation.get("blocked_path_ids")),
                    blocked_path_indices=self._as_int_list(recommendation.get("blocked_path_indices")),
                    fix_cost=self._as_float(recommendation.get("fix_cost")),
                    edge_score=self._as_float(recommendation.get("edge_score")),
                    covered_risk=self._as_float(recommendation.get("covered_risk")),
                    cumulative_risk_reduction=self._as_float(recommendation.get("cumulative_risk_reduction")),
                    metadata_json=self._as_dict(recommendation.get("metadata")),
                )
            )

        await self._session.commit()

    async def persist_graph(
        self,
        *,
        graph_id: str,
        graph: Any,
    ) -> None:
        logger.info(
            "analysis.persist_graph.entered",
            extra={
                "event": "analysis.persist_graph.entered",
                "repository_class": type(self).__name__,
                "repository_module": type(self).__module__,
                "graph_id": graph_id,
                "edge_count": graph.number_of_edges(),
            },
        )
        graph_node_columns = await self._get_table_columns("graph_nodes")
        graph_edge_columns = await self._get_table_columns("graph_edges")
        persisted_edge_ids_by_key = self._build_graph_edge_id_map(graph_id=graph_id, graph=graph)
        fact_rows = await self._fact_rows_by_graph(graph_id=graph_id)
        fact_ids_by_semantic_key = self._fact_id_lookup_from_rows(graph_id=graph_id, fact_rows=fact_rows)

        await self._session.execute(text("DELETE FROM graph_nodes WHERE graph_id = :graph_id"), {"graph_id": graph_id})
        await self._session.execute(text("DELETE FROM graph_edges WHERE graph_id = :graph_id"), {"graph_id": graph_id})

        node_rows = [
            self._graph_node_row(
                graph_node_columns=graph_node_columns,
                graph_id=graph_id,
                node_id=node_id,
                attrs=attrs,
            )
            for node_id, attrs in graph.nodes(data=True)
        ]
        edge_rows: list[dict[str, Any]] = []
        matched_edge_count = 0
        unmatched_edge_count = 0
        unmatched_by_edge_type: dict[str, int] = {}
        for source, target, attrs in graph.edges(data=True):
            source_node_id = str(source)
            target_node_id = str(target)
            edge_type = self._as_str(attrs.get("type")) or ""
            edge_lookup_key = (source_node_id, target_node_id, edge_type)
            matched_fact_id = fact_ids_by_semantic_key.get(edge_lookup_key)
            if matched_fact_id is not None:
                matched_edge_count += 1
            else:
                unmatched_edge_count += 1
                unmatched_by_edge_type[edge_type] = unmatched_by_edge_type.get(edge_type, 0) + 1
                if unmatched_edge_count <= 20:
                    logger.debug(
                        "analysis.persist_graph.unmatched_fact_edge",
                        extra={
                            "graph_id": graph_id,
                            "edge_key": edge_lookup_key,
                            "edge_metadata": self._as_dict(attrs.get("metadata")),
                            "matched_fact_id": matched_fact_id,
                        },
                    )

            edge_rows.append(self._graph_edge_row(
                graph_edge_columns=graph_edge_columns,
                graph_id=graph_id,
                source=source,
                target=target,
                attrs=attrs,
                persisted_edge_ids_by_key=persisted_edge_ids_by_key,
                fact_ids_by_semantic_key=fact_ids_by_semantic_key,
            ))

        print(
            "analysis.edge_match_summary",
            {
                "event": "analysis.edge_match_summary",
                "graph_id": graph_id,
                "fact_row_count": len(fact_rows),
                "fact_lookup_size": len(fact_ids_by_semantic_key),
                "total_edge_count": len(edge_rows),
                "matched_edge_count": matched_edge_count,
                "unmatched_edge_count": unmatched_edge_count,
                "unmatched_by_edge_type": unmatched_by_edge_type,
            },
        )

        await self._bulk_insert_rows("graph_nodes", node_rows)
        await self._bulk_insert_rows("graph_edges", edge_rows)
        await self._session.commit()

    async def persist_facts(
        self,
        *,
        cluster_id: str | UUID,
        analysis_job_id: str | None,
        graph_id: str,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        facts: list[Fact],
    ) -> None:
        facts_table = await self._reflect_table("facts")
        if facts_table is None:
            return
        fact_columns = set(facts_table.c.keys())

        delete_sql, delete_params = self._facts_delete_statement(
            fact_columns=fact_columns,
            cluster_id=str(cluster_id),
            analysis_job_id=analysis_job_id,
            graph_id=graph_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )
        if delete_sql is not None:
            await self._session.execute(text(delete_sql), delete_params)

        rows = [
            self._fact_row(
                fact_columns=fact_columns,
                cluster_id=str(cluster_id),
                analysis_job_id=analysis_job_id,
                graph_id=graph_id,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
                fact=fact,
                facts_table=facts_table,
            )
            for fact in facts
        ]
        if rows and rows[0]:
            await self._session.execute(facts_table.insert(), rows)
        await self._session.commit()

    async def finalize_graph_snapshot(
        self,
        *,
        graph_id: str,
        node_count: int,
        edge_count: int,
        entry_point_count: int,
        crown_jewel_count: int,
    ) -> None:
        snapshot = await self._session.get(GraphSnapshot, graph_id)
        if snapshot is None:
            return None

        snapshot.status = "completed"
        snapshot.node_count = node_count
        snapshot.edge_count = edge_count
        snapshot.entry_point_count = entry_point_count
        snapshot.crown_jewel_count = crown_jewel_count
        snapshot.completed_at = datetime.utcnow()
        await self._session.commit()

    async def _ensure_graph_snapshot(
        self,
        *,
        graph_id: str | None,
        cluster_id: str,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
    ) -> str:
        normalized_graph_id = self._normalize_graph_id(graph_id)
        if normalized_graph_id is not None:
            snapshot = await self._session.get(GraphSnapshot, normalized_graph_id)
            if snapshot is None:
                snapshot = GraphSnapshot(
                    id=normalized_graph_id,
                    cluster_id=cluster_id,
                    k8s_scan_id=k8s_scan_id,
                    aws_scan_id=aws_scan_id,
                    image_scan_id=image_scan_id,
                )
                self._session.add(snapshot)
                await self._session.flush()
            else:
                snapshot.cluster_id = cluster_id
                snapshot.k8s_scan_id = k8s_scan_id
                snapshot.aws_scan_id = aws_scan_id
                snapshot.image_scan_id = image_scan_id
            return snapshot.id

        snapshot = GraphSnapshot(
            cluster_id=cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )
        self._session.add(snapshot)
        await self._session.flush()
        return snapshot.id

    @staticmethod
    def _risk_level(value: Any) -> str:
        score = SqlAlchemyAnalysisJobRepository._as_float(value) or 0.0
        if score >= 0.9:
            return "critical"
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        if score > 0:
            return "low"
        return "none"

    @staticmethod
    def _path_title(path: Dict[str, Any]) -> str:
        nodes = [str(node_id) for node_id in path.get("path", [])]
        if len(nodes) >= 2:
            return f"{nodes[0]} -> {nodes[-1]}"
        return str(path.get("path_id", "attack-path"))

    @staticmethod
    def _attack_path_row_id(path_id: str) -> str:
        return str(uuid4())

    @staticmethod
    def _path_edge_row_id(path_id: str, edge_index: int) -> str:
        return str(uuid4())

    @staticmethod
    def _as_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_str(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, dict) else {}

    @staticmethod
    def _as_bool(value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes"}:
                return True
            if normalized in {"false", "0", "no"}:
                return False
        return None

    @staticmethod
    def _as_str_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value]

    @staticmethod
    def _as_int_list(value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        normalized: list[int] = []
        for item in value:
            try:
                normalized.append(int(item))
            except (TypeError, ValueError):
                continue
        return normalized

    @staticmethod
    def _normalize_graph_id(value: Any) -> str | None:
        if value is None:
            return None
        try:
            return str(UUID(str(value)))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _node_label(node_id: str, attrs: dict[str, Any]) -> str:
        label = attrs.get("label") or attrs.get("display_name") or attrs.get("name")
        if label is None:
            return str(node_id)
        return str(label)

    @staticmethod
    def _node_namespace(metadata: dict[str, Any]) -> str | None:
        for key in ("namespace", "account_id", "account", "aws_account_id"):
            value = metadata.get(key)
            if value is not None:
                return str(value)
        return None

    @staticmethod
    def _graph_edge_key(source: Any, target: Any, attrs: dict[str, Any], index: int) -> str:
        return SqlAlchemyAnalysisJobRepository._graph_edge_key_from_values(
            source=source,
            target=target,
            edge_type=attrs.get("type"),
        )

    @staticmethod
    def _graph_edge_key_from_values(source: Any, target: Any, edge_type: Any) -> str:
        normalized_type = str(edge_type or "edge")
        return f"{source}->{target}:{normalized_type}"

    @staticmethod
    def _graph_edge_uuid(graph_id: str, semantic_edge_key: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"{graph_id}:{semantic_edge_key}"))

    def _build_graph_edge_id_map(self, *, graph_id: str, graph: Any) -> dict[str, str]:
        persisted_edge_ids_by_key: dict[str, str] = {}
        for source, target, attrs in graph.edges(data=True):
            semantic_edge_key = self._graph_edge_key_from_values(source, target, attrs.get("type"))
            persisted_edge_ids_by_key.setdefault(
                semantic_edge_key,
                self._graph_edge_uuid(graph_id, semantic_edge_key),
            )
        return persisted_edge_ids_by_key

    async def _get_table_columns(self, table_name: str) -> set[str]:
        conn = await self._session.connection()

        def _inspect_columns(sync_conn):
            inspector = inspect(sync_conn)
            if not inspector.has_table(table_name):
                return set()
            return {column["name"] for column in inspector.get_columns(table_name)}

        return await conn.run_sync(_inspect_columns)

    async def _reflect_table(self, table_name: str) -> Table | None:
        conn = await self._session.connection()

        def _load_table(sync_conn):
            inspector = inspect(sync_conn)
            if not inspector.has_table(table_name):
                return None
            metadata = MetaData()
            return Table(table_name, metadata, autoload_with=sync_conn)

        return await conn.run_sync(_load_table)

    async def _bulk_insert_rows(self, table_name: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        if not rows[0]:
            return

        columns = list(rows[0].keys())
        placeholders = ", ".join(f":{column}" for column in columns)
        column_sql = ", ".join(columns)
        await self._session.execute(
            text(f"INSERT INTO {table_name} ({column_sql}) VALUES ({placeholders})"),
            rows,
        )

    def _graph_node_row(
        self,
        *,
        graph_node_columns: set[str],
        graph_id: str,
        node_id: Any,
        attrs: dict[str, Any],
    ) -> dict[str, Any]:
        metadata = self._as_dict(attrs.get("metadata"))
        row: dict[str, Any] = {}
        if "id" in graph_node_columns:
            row["id"] = str(uuid4())
        if "graph_id" in graph_node_columns:
            row["graph_id"] = graph_id
        if "node_id" in graph_node_columns:
            row["node_id"] = str(attrs.get("id") or node_id)
        if "node_type" in graph_node_columns:
            row["node_type"] = self._as_str(attrs.get("type")) or "unknown"
        if "label" in graph_node_columns:
            row["label"] = self._node_label(node_id, attrs)
        if "risk_level" in graph_node_columns:
            row["risk_level"] = self._risk_level(attrs.get("base_risk"))
        if "namespace" in graph_node_columns:
            row["namespace"] = self._node_namespace(metadata)
        if "base_risk" in graph_node_columns:
            row["base_risk"] = self._as_float(attrs.get("base_risk"))
        if "has_runtime_evidence" in graph_node_columns:
            row["has_runtime_evidence"] = self._as_bool(metadata.get("has_runtime_evidence"))
        if "is_entry_point" in graph_node_columns:
            row["is_entry_point"] = self._as_bool(attrs.get("is_entry_point"))
        if "is_crown_jewel" in graph_node_columns:
            row["is_crown_jewel"] = self._as_bool(attrs.get("is_crown_jewel"))
        metadata_col = "metadata" if "metadata" in graph_node_columns else None
        if metadata_col is not None:
            row[metadata_col] = json.dumps(metadata)
        return row

    def _attack_path_row(
        self,
        *,
        attack_path_columns: set[str],
        graph_id: str,
        persisted_path_row_id: str,
        path_id: str,
        node_ids: list[str],
        path: dict[str, Any],
    ) -> dict[str, Any]:
        row: dict[str, Any] = {}
        if "id" in attack_path_columns:
            row["id"] = persisted_path_row_id
        if "graph_id" in attack_path_columns:
            row["graph_id"] = graph_id
        if "path_id" in attack_path_columns:
            row["path_id"] = path_id
        if "risk_level" in attack_path_columns:
            row["risk_level"] = self._risk_level(path.get("raw_final_risk", path.get("risk_score")))
        if "risk_score" in attack_path_columns:
            row["risk_score"] = self._as_float(path.get("risk_score"))
        if "raw_final_risk" in attack_path_columns:
            row["raw_final_risk"] = self._as_float(path.get("raw_final_risk", path.get("risk_score")))
        if "hop_count" in attack_path_columns:
            row["hop_count"] = max(len(node_ids) - 1, 0)
        if "entry_node_id" in attack_path_columns:
            row["entry_node_id"] = node_ids[0] if node_ids else None
        if "target_node_id" in attack_path_columns:
            row["target_node_id"] = node_ids[-1] if node_ids else None
        if "node_ids" in attack_path_columns:
            row["node_ids"] = json.dumps(node_ids)
        return row

    def _attack_path_node_row(
        self,
        *,
        attack_path_node_columns: set[str],
        graph_id: str,
        persisted_path_row_id: str,
        node_id: str,
        position: int,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {}
        fk_column = self._attack_path_nodes_fk_column(attack_path_node_columns)
        position_column = self._attack_path_nodes_position_column(attack_path_node_columns)

        if "id" in attack_path_node_columns:
            row["id"] = self._attack_path_node_row_id(persisted_path_row_id, position, node_id)
        if "graph_id" in attack_path_node_columns:
            row["graph_id"] = graph_id
        if fk_column is not None:
            row[fk_column] = persisted_path_row_id
        if "node_id" in attack_path_node_columns:
            row["node_id"] = node_id
        if position_column is not None:
            row[position_column] = position
        return row

    @staticmethod
    def _is_persistable_attack_path(node_ids: list[str]) -> bool:
        return len(node_ids) > 1 and node_ids[0] != node_ids[-1]

    @staticmethod
    def _attack_path_nodes_fk_column(columns: set[str]) -> str | None:
        for candidate in ("attack_path_id", "path_id"):
            if candidate in columns:
                return candidate
        return None

    @staticmethod
    def _attack_path_nodes_position_column(columns: set[str]) -> str | None:
        for candidate in ("position", "sequence"):
            if candidate in columns:
                return candidate
        return None

    @staticmethod
    def _attack_path_node_row_id(persisted_path_row_id: str, position: int, node_id: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"{persisted_path_row_id}:{position}:{node_id}"))

    def _graph_edge_row(
        self,
        *,
        graph_edge_columns: set[str],
        graph_id: str,
        source: Any,
        target: Any,
        attrs: dict[str, Any],
        persisted_edge_ids_by_key: dict[str, str],
        fact_ids_by_semantic_key: dict[tuple[str, str, str], str],
    ) -> dict[str, Any]:
        row: dict[str, Any] = {}
        source_node_id = str(source)
        target_node_id = str(target)
        edge_type = self._as_str(attrs.get("type"))
        semantic_edge_key = self._graph_edge_key_from_values(source, target, attrs.get("type"))
        if "id" in graph_edge_columns:
            row["id"] = persisted_edge_ids_by_key[semantic_edge_key]
        if "graph_id" in graph_edge_columns:
            row["graph_id"] = graph_id
        if "source_node_id" in graph_edge_columns:
            row["source_node_id"] = source_node_id
        elif "source" in graph_edge_columns:
            row["source"] = source_node_id
        if "target_node_id" in graph_edge_columns:
            row["target_node_id"] = target_node_id
        elif "target" in graph_edge_columns:
            row["target"] = target_node_id
        if "fact_id" in graph_edge_columns:
            fact_lookup_key = (source_node_id, target_node_id, edge_type or "")
            fact_id = fact_ids_by_semantic_key.get(fact_lookup_key)
            row["fact_id"] = fact_id
            if fact_id is None:
                logger.debug(
                    "analysis.persist_graph.unmatched_fact_edge",
                    extra={
                        "graph_id": graph_id,
                        "source_node_id": source_node_id,
                        "target_node_id": target_node_id,
                        "edge_type": edge_type,
                    },
                )
        if "edge_type" in graph_edge_columns:
            row["edge_type"] = edge_type
        elif "type" in graph_edge_columns:
            row["type"] = edge_type
        metadata_col = "metadata" if "metadata" in graph_edge_columns else None
        if metadata_col is not None:
            row[metadata_col] = json.dumps(self._as_dict(attrs.get("metadata")))
        return row

    async def _fact_rows_by_graph(self, *, graph_id: str) -> list[dict[str, str]]:
        facts_table = await self._reflect_table("facts")
        if facts_table is None:
            logger.debug(
                "analysis.persist_graph.fact_lookup_missing_facts_table",
                extra={"graph_id": graph_id},
            )
            return []

        fact_columns = set(facts_table.c.keys())
        required_columns = {"graph_id", "id", "subject_id", "object_id", "fact_type"}
        if not required_columns.issubset(fact_columns):
            logger.debug(
                "analysis.persist_graph.fact_lookup_missing_columns",
                extra={
                    "graph_id": graph_id,
                    "fact_columns": sorted(fact_columns),
                },
            )
            return []

        result = await self._session.execute(
            select(
                facts_table.c.id,
                facts_table.c.subject_id,
                facts_table.c.object_id,
                facts_table.c.fact_type,
            ).where(facts_table.c.graph_id == graph_id)
        )

        fact_rows = result.mappings().all()
        logger.debug(
            "analysis.persist_graph.fact_rows_loaded",
            extra={
                "graph_id": graph_id,
                "fact_row_count": len(fact_rows),
                "fact_row_samples": [
                    {
                        "id": str(row["id"]),
                        "fact_type": str(row["fact_type"]),
                        "subject_id": str(row["subject_id"]),
                        "object_id": str(row["object_id"]),
                    }
                    for row in fact_rows[:5]
                ],
            },
        )
        return [
            {
                "id": str(row["id"]),
                "subject_id": str(row["subject_id"]),
                "object_id": str(row["object_id"]),
                "fact_type": str(row["fact_type"]),
            }
            for row in fact_rows
        ]

    def _fact_id_lookup_from_rows(
        self,
        *,
        graph_id: str,
        fact_rows: list[dict[str, str]],
    ) -> dict[tuple[str, str, str], str]:
        lookup: dict[tuple[str, str, str], str] = {}
        for row in fact_rows:
            key = (row["subject_id"], row["object_id"], row["fact_type"])
            lookup.setdefault(key, row["id"])
        logger.debug(
            "analysis.persist_graph.fact_lookup_built",
            extra={
                "graph_id": graph_id,
                "fact_lookup_size": len(lookup),
                "fact_lookup_key_samples": list(lookup.keys())[:10],
            },
        )
        return lookup


    def _facts_delete_statement(
        self,
        *,
        fact_columns: set[str],
        cluster_id: str,
        analysis_job_id: str | None,
        graph_id: str,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
    ) -> tuple[str | None, dict[str, Any]]:
        if "graph_id" in fact_columns:
            return "DELETE FROM facts WHERE graph_id = :graph_id", {"graph_id": graph_id}
        if analysis_job_id is not None and "analysis_job_id" in fact_columns:
            return "DELETE FROM facts WHERE analysis_job_id = :analysis_job_id", {"analysis_job_id": analysis_job_id}

        clauses: list[str] = []
        params: dict[str, Any] = {}
        if "cluster_id" in fact_columns:
            clauses.append("cluster_id = :cluster_id")
            params["cluster_id"] = cluster_id
        if "k8s_scan_id" in fact_columns:
            if k8s_scan_id is None:
                clauses.append("k8s_scan_id IS NULL")
            else:
                clauses.append("k8s_scan_id = :k8s_scan_id")
                params["k8s_scan_id"] = k8s_scan_id
        if "aws_scan_id" in fact_columns:
            if aws_scan_id is None:
                clauses.append("aws_scan_id IS NULL")
            else:
                clauses.append("aws_scan_id = :aws_scan_id")
                params["aws_scan_id"] = aws_scan_id
        if "image_scan_id" in fact_columns:
            if image_scan_id is None:
                clauses.append("image_scan_id IS NULL")
            else:
                clauses.append("image_scan_id = :image_scan_id")
                params["image_scan_id"] = image_scan_id
        if not clauses:
            return None, {}
        return f"DELETE FROM facts WHERE {' AND '.join(clauses)}", params

    def _fact_row(
        self,
        *,
        fact_columns: set[str],
        cluster_id: str,
        analysis_job_id: str | None,
        graph_id: str,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        fact: Fact,
        facts_table: Table,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {}
        if "id" in fact_columns:
            row["id"] = str(uuid4())
        if "analysis_job_id" in fact_columns:
            row["analysis_job_id"] = analysis_job_id
        if "graph_id" in fact_columns:
            row["graph_id"] = graph_id
        if "cluster_id" in fact_columns:
            row["cluster_id"] = cluster_id
        if "k8s_scan_id" in fact_columns:
            row["k8s_scan_id"] = k8s_scan_id
        if "aws_scan_id" in fact_columns:
            row["aws_scan_id"] = aws_scan_id
        if "image_scan_id" in fact_columns:
            row["image_scan_id"] = image_scan_id
        if "scan_id" in fact_columns:
            row["scan_id"] = self._fact_scan_id(
                fact=fact,
                k8s_scan_id=k8s_scan_id,
                aws_scan_id=aws_scan_id,
                image_scan_id=image_scan_id,
            )
        if "fact_type" in fact_columns:
            row["fact_type"] = fact.fact_type
        if "subject_id" in fact_columns:
            row["subject_id"] = fact.subject_id
        if "subject_type" in fact_columns:
            row["subject_type"] = fact.subject_type
        if "object_id" in fact_columns:
            row["object_id"] = fact.object_id
        if "object_type" in fact_columns:
            row["object_type"] = fact.object_type
        if "created_at" in fact_columns:
            row["created_at"] = self._fact_created_at_value(fact.created_at)
        metadata_col = "metadata" if "metadata" in fact_columns else ("metadata_json" if "metadata_json" in fact_columns else None)
        if metadata_col is not None:
            row[metadata_col] = self._fact_metadata_value(
                facts_table.c[metadata_col],
                self._as_dict(fact.metadata),
            )
        return row

    @staticmethod
    def _fact_scan_id(
        *,
        fact: Fact,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
    ) -> str | None:
        persisted_scan_id = getattr(fact, "_persisted_scan_id", None)
        if persisted_scan_id is not None:
            normalized = str(persisted_scan_id).strip()
            if normalized:
                return normalized
        for candidate in (k8s_scan_id, aws_scan_id, image_scan_id):
            if candidate is not None and str(candidate).strip():
                return str(candidate)
        return None

    @staticmethod
    def _fact_created_at_value(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str) and value:
            normalized = value.strip()
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(normalized)
                return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _fact_metadata_value(column, metadata: dict[str, Any]) -> Any:
        column_type_name = type(column.type).__name__.lower()
        if "json" in column_type_name:
            return metadata
        return json.dumps(metadata)
