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
