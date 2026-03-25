from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.application.services.attack_graph_service import AttackGraphService


class FakeClusterRepository:
    async def get_by_id(self, cluster_id: str):
        return {"id": cluster_id}


@pytest.mark.asyncio
async def test_get_remediation_recommendations_normalizes_uuid_analysis_run_id_for_empty_list():
    service = AttackGraphService(cluster_repository=FakeClusterRepository(), db=SimpleNamespace())

    async def fake_get_latest_analysis_context(cluster_id: str):
        return {
            "analysis_run_id": uuid4(),
            "graph_id": "graph-empty",
            "generated_at": None,
        }

    async def fake_get_remediation_recommendation_items(graph_id: str):
        assert graph_id == "graph-empty"
        return []

    service._get_latest_analysis_context = fake_get_latest_analysis_context
    service._get_remediation_recommendation_items = fake_get_remediation_recommendation_items

    response = await service.get_remediation_recommendations("cluster-1")

    assert isinstance(response.analysis_run_id, str)
    assert response.analysis_run_id
    assert response.items == []


@pytest.mark.asyncio
async def test_get_remediation_recommendations_normalizes_uuid_analysis_run_id_for_non_empty_list():
    service = AttackGraphService(cluster_repository=FakeClusterRepository(), db=SimpleNamespace())
    analysis_run_id = uuid4()

    async def fake_get_latest_analysis_context(cluster_id: str):
        return {
            "analysis_run_id": analysis_run_id,
            "graph_id": "graph-ranked",
            "generated_at": None,
        }

    async def fake_get_remediation_recommendation_items(graph_id: str):
        assert graph_id == "graph-ranked"
        return []

    service._get_latest_analysis_context = fake_get_latest_analysis_context
    service._get_remediation_recommendation_items = fake_get_remediation_recommendation_items

    response = await service.get_remediation_recommendations("cluster-1")

    assert response.analysis_run_id == str(analysis_run_id)
    assert response.items == []
