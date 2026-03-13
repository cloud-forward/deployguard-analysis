"""
Domain repository interfaces (protocols) for analysis jobs and results.
These are implemented by gateway adapters (e.g., SQLAlchemy).
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable, Any, Dict, Optional


@runtime_checkable
class AnalysisJobRepository(Protocol):
    async def create_job(self, target_id: str, params: Dict[str, Any]) -> str:
        """Create a new analysis job. Returns job_id."""
        ...

    async def mark_started(self, job_id: str) -> None:
        ...

    async def mark_completed(self, job_id: str, summary: Dict[str, Any]) -> None:
        ...

    async def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        ...

    async def create_analysis_job(self, cluster_id: str, k8s_scan_id: str, aws_scan_id: str, image_scan_id: str) -> str:
        """Create an analysis job for a cluster with all required scan IDs. Returns job_id."""
        ...


