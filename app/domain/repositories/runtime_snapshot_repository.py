"""
Domain repository interface for runtime snapshot persistence.
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class RuntimeSnapshotRepository(Protocol):
    async def create(
        self,
        cluster_id: str,
        s3_key: str,
        snapshot_at: datetime,
        uploaded_at: datetime,
        fact_count: int | None = None,
    ) -> object:
        """Persist a confirmed runtime snapshot row."""
        ...

    async def get_by_s3_key(self, s3_key: str) -> object | None:
        """Fetch a runtime snapshot by unique s3_key."""
        ...

    async def get_latest_by_cluster_id(self, cluster_id: str) -> object | None:
        """Fetch the most recently uploaded runtime snapshot for a cluster."""
        ...

    async def list_recent_by_cluster_id(self, cluster_id: str, limit: int) -> list[object]:
        """Fetch recent runtime snapshots for a cluster ordered by uploaded_at desc."""
        ...
