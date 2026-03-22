"""
SQLAlchemy ORM models for PostgreSQL. Gateway layer only.
Moved from app/models/db_models.py to avoid domain→gateway dependency.
"""
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import (
    String,
    JSON,
    DateTime,
    Boolean,
    Integer,
    Text,
    CheckConstraint,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from uuid import uuid4
from datetime import datetime
from app.gateway.db.base import Base
from app.core.constants import (
    SCAN_STATUS_CREATED,
    SCAN_STATUS_PENDING,
    SCANNER_TYPE_AWS,
    SCANNER_TYPE_IMAGE,
    SCANNER_TYPE_K8S,
)


JSONB_COMPAT = JSON().with_variant(JSONB, "postgresql")
UUID_COMPAT = UUID(as_uuid=False).with_variant(String(36), "sqlite")


class MergeState(Base):
    """
    Model representing the state of alert merging processes.
    """
    __tablename__ = "merge_states"

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(50))
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AlertGroup(Base):
    """
    SQLAlchemy model for alert_groups.

    Worker selection priority (clarification):
    - Step 1 (FINAL FIRST): WHERE is_open = TRUE AND window_expires_at <= now()
    - Step 2 (DEBOUNCE SECOND): WHERE is_open = TRUE AND window_expires_at > now() AND next_reanalysis_at <= now()

    Sliding window safety note:
    - last_updated_at MUST be explicitly updated in UPSERT.
    - window_expires_at depends on last_updated_at.
    - ORM onupdate is NOT sufficient for ON CONFLICT statements.
    """

    __tablename__ = "alert_groups"

    id: Mapped[int] = mapped_column(primary_key=True)

    pod_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attacker_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_open: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("TRUE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    last_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    window_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_reanalysis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    merge_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    runtime_bonus_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    reanalyze_on_next_ingest: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    reanalyze_manual_request: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    reanalyze_due_to_runtime_bonus: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class GraphSnapshot(Base):
    __tablename__ = "graph_snapshots"

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'fact_extraction', 'graph_building', 'path_discovery', "
            "'risk_calculation', 'optimization', 'completed', 'failed')",
            name="ck_analysis_jobs_status",
        ),
        Index("idx_analysis_jobs_cluster_id", "cluster_id"),
        Index("idx_analysis_jobs_status", "status"),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    cluster_id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        ForeignKey("clusters.id"),
        nullable=False,
    )
    graph_id: Mapped[str | None] = mapped_column(
        UUID_COMPAT,
        ForeignKey("graph_snapshots.id"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=SCAN_STATUS_PENDING,
        server_default=text("'pending'"),
    )
    current_step: Mapped[str | None] = mapped_column(String(100), nullable=True)
    k8s_scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    aws_scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=text("now()"),
    )


class AttackPath(Base):
    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("idx_attack_paths_graph_id", "graph_id"),
        Index("idx_attack_paths_entry_node_id", "entry_node_id"),
        Index("idx_attack_paths_target_node_id", "target_node_id"),
        Index("idx_attack_paths_graph_path_id", "graph_id", "path_id", unique=True),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    graph_id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        ForeignKey("graph_snapshots.id"),
        nullable=False,
    )
    path_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    raw_final_risk: Mapped[float | None] = mapped_column(nullable=True)
    hop_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    entry_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    node_ids: Mapped[list | None] = mapped_column(JSONB_COMPAT, nullable=True)
    edge_ids: Mapped[list | None] = mapped_column(JSONB_COMPAT, nullable=True)


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"
    __table_args__ = (
        Index("idx_attack_path_edges_graph_id", "graph_id"),
        Index("idx_attack_path_edges_graph_path_id", "graph_id", "path_id"),
        Index("idx_attack_path_edges_graph_path_order", "graph_id", "path_id", "edge_index"),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    graph_id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        ForeignKey("graph_snapshots.id"),
        nullable=False,
    )
    path_id: Mapped[str] = mapped_column(String(255), nullable=False)
    edge_id: Mapped[str] = mapped_column(String(255), nullable=False)
    edge_index: Mapped[int] = mapped_column(Integer, nullable=False)
    source_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(100), nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB_COMPAT, nullable=True)


class RemediationRecommendation(Base):
    __tablename__ = "remediation_recommendations"
    __table_args__ = (
        Index("idx_remediation_recommendations_graph_id", "graph_id"),
        Index("idx_remediation_recommendations_graph_rank", "graph_id", "recommendation_rank"),
        Index("idx_remediation_recommendations_graph_fix_type", "graph_id", "fix_type"),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    graph_id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        ForeignKey("graph_snapshots.id"),
        nullable=False,
    )
    recommendation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    recommendation_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    edge_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    edge_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    edge_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fix_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fix_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    blocked_path_ids: Mapped[list | None] = mapped_column(JSONB_COMPAT, nullable=True)
    blocked_path_indices: Mapped[list | None] = mapped_column(JSONB_COMPAT, nullable=True)
    fix_cost: Mapped[float | None] = mapped_column(nullable=True)
    edge_score: Mapped[float | None] = mapped_column(nullable=True)
    covered_risk: Mapped[float | None] = mapped_column(nullable=True)
    cumulative_risk_reduction: Mapped[float | None] = mapped_column(nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB_COMPAT, nullable=True)


class Cluster(Base):
    """
    Model representing a cluster in DeployGuard.
    """
    __tablename__ = "clusters"

    id: Mapped[str] = mapped_column(UUID_COMPAT, primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    api_token: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    cluster_type: Mapped[str] = mapped_column(String(50), nullable=False)
    aws_account_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    aws_role_arn: Mapped[str | None] = mapped_column(String, nullable=True)
    aws_region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"
    __table_args__ = (
        Index("idx_inventory_snapshots_cluster_id", "cluster_id"),
        Index("idx_inventory_snapshots_scanned_at", text("scanned_at DESC")),
        Index("idx_inventory_snapshots_cluster_scanned_at", "cluster_id", text("scanned_at DESC")),
        Index(
            "uq_inventory_snapshots_cluster_scan_id",
            "cluster_id",
            "scan_id",
            unique=True,
            postgresql_where=text("scan_id IS NOT NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    cluster_id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        ForeignKey("clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=text("now()"),
    )
    raw_result_json: Mapped[dict] = mapped_column(JSONB_COMPAT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=text("now()"),
    )


class ScanRecord(Base):
    __tablename__ = "scan_records"
    __table_args__ = (
        CheckConstraint(
            f"scanner_type IN ('{SCANNER_TYPE_K8S}', '{SCANNER_TYPE_AWS}', '{SCANNER_TYPE_IMAGE}')",
            name="ck_scan_records_scanner_type",
        ),
        CheckConstraint(
            "status IN ('created', 'uploading', 'processing', 'completed', 'failed')",
            name="ck_scan_records_status",
        ),
        Index("idx_scan_records_scan_id", "scan_id"),
        Index("idx_scan_records_cluster_id", "cluster_id"),
        Index("idx_scan_records_status", "status"),
        Index("idx_scan_records_created_at", text("created_at DESC")),
    )

    id: Mapped[str] = mapped_column(
        UUID_COMPAT,
        primary_key=True,
        default=lambda: str(uuid4()),
        server_default=text("gen_random_uuid()"),
    )
    scan_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    cluster_id: Mapped[str] = mapped_column(
        String(255),          # DB에 VARCHAR 로 저장되어 있으므로 String 으로 선언
        ForeignKey("clusters.id"),
        nullable=False,
    )
    scanner_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=SCAN_STATUS_CREATED,
        server_default=text("'created'"),
    )
    s3_keys: Mapped[list] = mapped_column(
        JSONB_COMPAT,
        nullable=False,
        default=list,
        server_default=text("'[]'"),
    )
    # DB 실제 컬럼 목록에 맞춰 선언
    # error_message, updated_at 은 DB 에 없으므로 제거
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=text("now()"),
    )
    request_source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="manual",
        server_default=text("'manual'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=text("now()"),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    analysis_run_id: Mapped[str | None] = mapped_column(UUID_COMPAT, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __init__(self, **kwargs):
        kwargs.setdefault("status", SCAN_STATUS_CREATED)
        kwargs.setdefault("s3_keys", [])
        super().__init__(**kwargs)
