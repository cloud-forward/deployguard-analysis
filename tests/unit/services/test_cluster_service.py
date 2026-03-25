from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.application.services.cluster_service import ClusterService
from app.models.schemas import ClusterCreateRequest


@pytest.mark.asyncio
async def test_create_cluster_passes_user_id_through_to_repository():
    repo = AsyncMock()
    repo.get_by_name.return_value = None
    repo.create.return_value = SimpleNamespace(
        id="cluster-1",
        name="owned-cluster",
        cluster_type="eks",
        description=None,
        api_token="dg_scanner_test",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        aws_account_id=None,
        aws_role_arn=None,
        aws_region=None,
    )
    service = ClusterService(cluster_repository=repo)

    await service.create_cluster(
        ClusterCreateRequest(name="owned-cluster", cluster_type="eks"),
        user_id="user-42",
    )

    repo.create.assert_awaited_once()
    assert repo.create.await_args.kwargs["user_id"] == "user-42"


@pytest.mark.asyncio
async def test_list_clusters_passes_user_id_through_to_repository():
    repo = AsyncMock()
    repo.list_all.return_value = [
        SimpleNamespace(
            id="cluster-1",
            name="owned-cluster",
            cluster_type="eks",
            description=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            aws_account_id=None,
            aws_role_arn=None,
            aws_region=None,
        )
    ]
    service = ClusterService(cluster_repository=repo)

    result = await service.list_clusters(user_id="user-42")

    repo.list_all.assert_awaited_once_with("user-42")
    assert [cluster.name for cluster in result] == ["owned-cluster"]
