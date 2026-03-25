from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.gateway.db.base import Base
from app.gateway.models import User
from app.gateway.repositories.cluster_repository import SQLAlchemyClusterRepository


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as session:
        session.add(
            User(
                id="user-1",
                email="user-1@example.com",
                password_hash="hashed-password",
                is_active=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )
        await session.commit()
        yield SQLAlchemyClusterRepository(session)

    await engine.dispose()


class TestSQLAlchemyClusterRepository:
    @pytest.mark.asyncio
    async def test_create_persists_user_id(self, repo):
        created = await repo.create(
            name="owned-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_test",
        )

        assert created.user_id == "user-1"

        found = await repo.get_by_id(created.id)
        assert found is not None
        assert found.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_get_by_id_returns_cluster_for_owning_user(self, repo):
        created = await repo.create(
            name="owned-detail-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_owned_detail",
        )

        found = await repo.get_by_id(created.id, user_id="user-1")

        assert found is not None
        assert found.id == created.id

    @pytest.mark.asyncio
    async def test_get_by_id_returns_none_for_other_user(self, repo):
        created = await repo.create(
            name="other-user-detail-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_other_user_detail",
        )

        found = await repo.get_by_id(created.id, user_id="user-2")

        assert found is None

    @pytest.mark.asyncio
    async def test_list_all_returns_only_clusters_for_requested_user(self, repo):
        await repo.create(
            name="user-1-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_user_1",
        )
        await repo.create(
            name="unowned-cluster",
            cluster_type="eks",
            user_id=None,
            api_token="dg_scanner_none",
        )

        found = await repo.list_all("user-1")

        assert [cluster.name for cluster in found] == ["user-1-cluster"]

    @pytest.mark.asyncio
    async def test_update_succeeds_for_owning_user(self, repo):
        created = await repo.create(
            name="owned-update-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_owned_update",
        )

        updated = await repo.update(created.id, user_id="user-1", description="updated")

        assert updated is not None
        assert updated.description == "updated"

    @pytest.mark.asyncio
    async def test_update_does_not_affect_other_users_cluster(self, repo):
        created = await repo.create(
            name="other-user-update-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_other_user_update",
        )

        updated = await repo.update(created.id, user_id="user-2", description="updated")
        found = await repo.get_by_id(created.id, user_id="user-1")

        assert updated is None
        assert found is not None
        assert found.description is None

    @pytest.mark.asyncio
    async def test_delete_succeeds_for_owning_user(self, repo):
        created = await repo.create(
            name="owned-delete-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_owned_delete",
        )

        deleted = await repo.delete(created.id, user_id="user-1")
        found = await repo.get_by_id(created.id, user_id="user-1")

        assert deleted is True
        assert found is None

    @pytest.mark.asyncio
    async def test_delete_does_not_affect_other_users_cluster(self, repo):
        created = await repo.create(
            name="other-user-delete-cluster",
            cluster_type="eks",
            user_id="user-1",
            api_token="dg_scanner_other_user_delete",
        )

        deleted = await repo.delete(created.id, user_id="user-2")
        found = await repo.get_by_id(created.id, user_id="user-1")

        assert deleted is False
        assert found is not None
