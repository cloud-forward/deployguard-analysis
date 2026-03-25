"""
Domain repository interfaces (protocols) for analysis jobs and results.
These are implemented by gateway adapters (e.g., SQLAlchemy).
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable, Any, Dict, Optional
from uuid import UUID
from src.facts.canonical_fact import Fact


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

    async def get_analysis_job(self, job_id: str, user_id: str | None = None) -> object | None:
        """Fetch a persisted analysis job record by id."""
        ...

    async def list_analysis_jobs(
        self,
        cluster_id: str | UUID,
        user_id: str,
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
        user_id: str | None = None,
    ) -> str:
        """Create an analysis job for a cluster with all required scan IDs. Returns job_id."""
        ...

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
        """Persist attack paths and link them to the latest matching analysis job/graph snapshot.

        Returns the real persisted graph snapshot id.
        """
        ...

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
        """Persist remediation optimization recommendations for the linked graph snapshot."""
        ...

    async def persist_graph(
        self,
        *,
        graph_id: str,
        graph: Any,
    ) -> None:
        """Persist graph nodes and edges for an existing graph snapshot."""
        ...

    async def finalize_graph_snapshot(
        self,
        *,
        graph_id: str,
        node_count: int,
        edge_count: int,
        entry_point_count: int,
        crown_jewel_count: int,
    ) -> None:
        """Finalize a graph snapshot with completed status and computed counts."""
        ...

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
        """Persist canonical facts for the current analysis execution."""
        ...

    async def rollback(self) -> None:
        """Rollback the current unit of work after a persistence failure."""
        ...
