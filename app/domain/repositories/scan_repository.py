"""
Domain repository interface (protocol) for ScanRecord persistence.
Implemented by gateway adapters (e.g., SQLAlchemy).
"""
from __future__ import annotations
from datetime import datetime
from typing import Protocol, runtime_checkable
from app.models.schemas import RequestSource


@runtime_checkable
class ScanRepository(Protocol):
    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        status: str = "created",
        request_source: RequestSource = "manual",
        requested_at: datetime | None = None,
    ) -> object:
        """Persist a new ScanRecord. Returns the created ScanRecord."""
        ...

    async def get_by_scan_id(self, scan_id: str) -> object | None:
        """Fetch a ScanRecord by scan_id. Returns None if not found."""
        ...

    async def update_status(self, scan_id: str, status: str, **kwargs) -> object:
        """Update the status (and optional fields) of a ScanRecord. Returns updated ScanRecord."""
        ...

    async def update(self, scan_id: str, status: str, s3_keys: list[str], completed_at=None) -> object:
        """Update status and s3_keys of a ScanRecord. Returns updated ScanRecord."""
        ...

    async def update_files(self, scan_id: str, s3_keys: list[str]) -> object:
        """Update the s3_keys list of a ScanRecord. Returns updated ScanRecord."""
        ...

    async def list_by_cluster(self, cluster_id: str) -> list:
        """Return all ScanRecords for a given cluster_id."""
        ...
    async def find_active_scan(self, cluster_id: str, scanner_type: str) -> object | None:
        """Return an active ScanRecord (status in created/processing/uploading) for the given cluster and scanner_type, or None."""
        ...
    async def get_latest_completed_scans(self, cluster_id: str) -> dict:
        """Return a dict mapping scanner_type -> latest completed ScanRecord for the given cluster."""
        ...

    async def claim_next_queued_scan(
        self,
        cluster_id: str,
        scanner_type: str,
        claimed_by: str,
        lease_expires_at: datetime,
        started_at: datetime,
    ) -> object | None:
        """Atomically claim one created scan for a worker. Returns claimed ScanRecord or None."""
        ...

    async def set_analysis_run_id(self, scan_id: str, analysis_run_id: str) -> object:
        """Attach an analysis run id to a scan record. Returns updated ScanRecord."""
        ...
