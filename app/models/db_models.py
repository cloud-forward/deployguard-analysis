"""
Deprecated: ORM models moved to gateway layer to enforce Clean Architecture boundaries.

Use models from: app.gateway.db.models
This module remains only as a compatibility shim and will be removed.
"""

# Re-export for backward compatibility if anything still imports this module.
from app.gateway.models import *  # noqa: F401,F403

from uuid import uuid4
from datetime import datetime
from sqlalchemy import String, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.gateway.db.base import Base
from app.core.constants import SCAN_STATUS_CREATED


class ScanRecord(Base):
    """
    Model representing a scan record submitted by a cluster scanner.
    """
    __tablename__ = "scan_records"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    cluster_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    scanner_type: Mapped[str] = mapped_column(String, nullable=False)  # k8s | aws | image | runtime
    status: Mapped[str] = mapped_column(String, nullable=False, default=SCAN_STATUS_CREATED)  # created | uploading | processing | completed | failed
    s3_keys: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __init__(self, **kwargs):
        kwargs.setdefault("status", SCAN_STATUS_CREATED)
        kwargs.setdefault("s3_keys", [])
        super().__init__(**kwargs)
