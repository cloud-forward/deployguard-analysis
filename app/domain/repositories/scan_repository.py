"""
Domain repository interface (protocol) for ScanRecord persistence.
Implemented by gateway adapters (e.g., SQLAlchemy).
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class ScanRepository(Protocol):
    async def create(self, scan_id: str, cluster_id: str, scanner_type: str) -> object:
        """Persist a new ScanRecord. Returns the created ScanRecord."""
        ...

    async def get_by_scan_id(self, scan_id: str) -> object | None:
        """Fetch a ScanRecord by scan_id. Returns None if not found."""
        ...

    async def update_status(self, scan_id: str, status: str, **kwargs) -> object:
        """Update the status (and optional fields) of a ScanRecord. Returns updated ScanRecord."""
        ...

    async def update_files(self, scan_id: str, s3_keys: list[str]) -> object:
        """Update the s3_keys list of a ScanRecord. Returns updated ScanRecord."""
        ...

    async def list_by_cluster(self, cluster_id: str) -> list:
        """Return all ScanRecords for a given cluster_id."""
        ...
    async def find_active_scan(self, cluster_id: str, scanner_type: str) -> object | None:
        """Return an active ScanRecord (status in created/uploading/processing) for the given cluster and scanner_type, or None."""
        ...
