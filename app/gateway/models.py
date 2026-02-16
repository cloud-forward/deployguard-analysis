"""
SQLAlchemy ORM models for PostgreSQL. Gateway layer only.
Moved from app/models/db_models.py to avoid domain→gateway dependency.
"""
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, JSON, DateTime, Boolean, Integer, text
from datetime import datetime
from app.gateway.db import Base


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

    # Identifiers/context
    pod_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attacker_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Lifecycle and scheduling
    is_open: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("TRUE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    last_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    window_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_reanalysis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Counters / signals
    merge_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    runtime_bonus_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    # Reanalysis flags
    reanalyze_on_next_ingest: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    reanalyze_manual_request: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    reanalyze_due_to_runtime_bonus: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))

    # Misc
    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
