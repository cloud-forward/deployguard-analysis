from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.gateway.db.base import Base
from app.gateway.models import LLMProviderConfig
from app.gateway.repositories.llm_provider_config_repository import SQLAlchemyLLMProviderConfigRepository


@pytest.fixture
async def repo_and_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield SQLAlchemyLLMProviderConfigRepository(session), session

    await engine.dispose()


@pytest.mark.asyncio
async def test_get_active_is_scoped_by_user_id(repo_and_session):
    repo, session = repo_and_session
    session.add_all(
        [
            LLMProviderConfig(user_id="user-1", provider="openai", api_key="u1-openai", default_model="gpt-4o-mini", is_active=True),
            LLMProviderConfig(user_id="user-2", provider="openai", api_key="u2-openai", default_model="gpt-4o-mini", is_active=True),
        ]
    )
    await session.commit()

    config = await repo.get_active("user-1")

    assert config is not None
    assert config.user_id == "user-1"
    assert config.api_key == "u1-openai"


@pytest.mark.asyncio
async def test_get_by_provider_is_scoped_by_user_id(repo_and_session):
    repo, session = repo_and_session
    session.add_all(
        [
            LLMProviderConfig(user_id="user-1", provider="xai", api_key="u1-xai", default_model="grok-3-mini", is_active=False),
            LLMProviderConfig(user_id="user-2", provider="xai", api_key="u2-xai", default_model="grok-3-mini", is_active=False),
        ]
    )
    await session.commit()

    config = await repo.get_by_provider("user-2", "xai")

    assert config is not None
    assert config.user_id == "user-2"
    assert config.api_key == "u2-xai"
