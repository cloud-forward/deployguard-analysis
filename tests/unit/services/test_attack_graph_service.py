from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.application.services.attack_graph_service import AttackGraphService


class FakeClusterRepository:
    async def get_by_id(self, cluster_id: str, user_id: str | None = None):
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


@pytest.mark.asyncio
async def test_get_attack_graph_returns_empty_payload_when_analysis_exists_but_no_persisted_rows():
    service = AttackGraphService(cluster_repository=FakeClusterRepository(), db=SimpleNamespace())
    analysis_run_id = uuid4()

    async def fake_get_latest_analysis_context(cluster_id: str):
        return {
            "analysis_run_id": analysis_run_id,
            "graph_id": "graph-empty",
            "generated_at": None,
        }

    async def fake_graph_has_persisted_rows(graph_id: str) -> bool:
        assert graph_id == "graph-empty"
        return False

    service._get_latest_analysis_context = fake_get_latest_analysis_context
    service._graph_has_persisted_rows = fake_graph_has_persisted_rows

    response = await service.get_attack_graph("cluster-1")

    assert response.cluster_id == "cluster-1"
    assert response.analysis_run_id == str(analysis_run_id)
    assert response.generated_at is None
    assert response.nodes == []
    assert response.edges == []
    assert response.paths == []


@pytest.mark.asyncio
async def test_get_attack_graph_serializes_uuid_analysis_run_id_in_non_empty_response():
    service = AttackGraphService(cluster_repository=FakeClusterRepository(), db=SimpleNamespace())
    analysis_run_id = uuid4()

    async def fake_get_latest_analysis_context(cluster_id: str):
        return {
            "analysis_run_id": analysis_run_id,
            "graph_id": "graph-non-empty",
            "generated_at": None,
        }

    async def fake_graph_has_persisted_rows(graph_id: str) -> bool:
        assert graph_id == "graph-non-empty"
        return True

    async def fake_get_nodes(graph_id: str):
        assert graph_id == "graph-non-empty"
        return []

    async def fake_get_edges(graph_id: str, *, valid_node_ids: set[str]):
        assert graph_id == "graph-non-empty"
        assert valid_node_ids == set()
        return []

    async def fake_get_paths(
        graph_id: str,
        *,
        valid_node_ids: set[str],
        valid_edge_ids: set[str],
        nodes_by_id: dict[str, object],
        edges_by_id: dict[str, object],
        node_labels: dict[str, str],
        edge_ids_by_pair: dict[tuple[str, str], str],
    ):
        assert graph_id == "graph-non-empty"
        assert valid_node_ids == set()
        assert valid_edge_ids == set()
        assert nodes_by_id == {}
        assert edges_by_id == {}
        assert node_labels == {}
        assert edge_ids_by_pair == {}
        return []

    service._get_latest_analysis_context = fake_get_latest_analysis_context
    service._graph_has_persisted_rows = fake_graph_has_persisted_rows
    service._get_nodes = fake_get_nodes
    service._get_edges = fake_get_edges
    service._get_paths = fake_get_paths

    response = await service.get_attack_graph("cluster-1")

    assert response.cluster_id == "cluster-1"
    assert response.analysis_run_id == str(analysis_run_id)
    assert response.generated_at is None
    assert response.nodes == []
    assert response.edges == []
    assert response.paths == []


@pytest.mark.asyncio
async def test_get_attack_paths_returns_empty_payload_when_analysis_exists_but_no_persisted_rows():
    service = AttackGraphService(cluster_repository=FakeClusterRepository(), db=SimpleNamespace())

    async def fake_get_latest_analysis_context(cluster_id: str):
        return {
            "analysis_run_id": uuid4(),
            "graph_id": "graph-empty",
            "generated_at": None,
        }

    async def fake_attack_paths_exist(graph_id: str) -> bool:
        assert graph_id == "graph-empty"
        return False

    service._get_latest_analysis_context = fake_get_latest_analysis_context
    service._attack_paths_exist = fake_attack_paths_exist

    response = await service.get_attack_paths("cluster-1")

    assert response.cluster_id == "cluster-1"
    assert isinstance(response.analysis_run_id, str)
    assert response.generated_at is None
    assert response.items == []
