"""
OpenSearch implementation of RiskResultRepository.
"""
from __future__ import annotations
from app.domain.repositories.analysis_jobs import RiskResultRepository
from typing import Any

try:
    from app.gateway.opensearch_client import get_opensearch_client  # existing infra module
except Exception:  # pragma: no cover - optional during skeleton phase
    get_opensearch_client = None  # type: ignore


class OpenSearchRiskResultRepository(RiskResultRepository):
    def __init__(self, client: Any | None = None):
        self._client = client

    async def persist_score(self, target_id: str, score: float) -> None:
        # TODO: implement OpenSearch index/write logic
        return None
