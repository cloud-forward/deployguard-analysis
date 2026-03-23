"""
Domain repository interfaces (protocols) for analysis jobs and results.
These are implemented by gateway adapters (e.g., SQLAlchemy).
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable, Any, Dict, Optional
from uuid import UUID


@runtime_checkable
class AnalysisJobRepository(Protocol):
    async def create_job(self, target_id: str, params: Dict[str, Any]) -> str:
        """Create a new analysis job. Returns job_id."""
        ...

    async def mark_started(self, job_id: str) -> None:
        ...

    async def mark_completed(self, job_id: str, summary: Dict[str, Any]) -> None:
        ...

    async def mark_running(self, job_id: str, current_step: str | None = None) -> None:
        ...

    async def update_current_step(self, job_id: str, current_step: str) -> None:
        ...

    async def mark_failed(self, job_id: str, error_message: str) -> None:
        ...

    async def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        ...

    async def get_analysis_job(self, job_id: str) -> object | None:
        """Fetch a persisted analysis job record by id."""
        ...

    async def list_analysis_jobs(
        self,
        cluster_id: str | UUID,
        status: str | None = None,
    ) -> list[object]:
        """List persisted analysis jobs for a cluster, optionally filtered by status."""
        ...

    async def create_analysis_job(
        self,
        cluster_id: str | UUID,
        k8s_scan_id: str | None,
        aws_scan_id: str | None,
        image_scan_id: str | None,
        expected_scans: list[str],
    ) -> str:
        """Create an analysis job for a cluster with all required scan IDs. Returns job_id."""
        ...

    async def persist_attack_paths(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        attack_paths: list[Dict[str, Any]],
    ) -> None:
        """Persist attack paths and link them to the latest matching analysis job/graph snapshot."""
        ...

    async def persist_remediation_recommendations(
        self,
        *,
        cluster_id: str | UUID,
        graph_id: str,
        k8s_scan_id: str,
        aws_scan_id: str,
        image_scan_id: str,
        remediation_optimization: Dict[str, Any],
    ) -> None:
        """Persist remediation optimization recommendations for the linked graph snapshot."""
        ...
