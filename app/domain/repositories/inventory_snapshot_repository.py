"""
Domain repository interface for Discovery Inventory snapshots.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class InventorySnapshotRepository(Protocol):
    async def create(self, cluster_id: str, scan_id: str, scanned_at, raw_result_json: dict) -> object:
        """Persist a Discovery Inventory snapshot."""
        ...

    async def get_latest_by_cluster(self, cluster_id: str) -> object | None:
        """Return the latest snapshot for a cluster."""
        ...

    async def list_latest(self) -> list[object]:
        """Return the latest snapshot per cluster."""
        ...
