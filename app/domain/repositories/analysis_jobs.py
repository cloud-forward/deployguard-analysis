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


