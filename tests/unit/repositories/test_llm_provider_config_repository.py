from __future__ import annotations

from datetime import datetime

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


@pytest.mark.asyncio
async def test_list_by_user_returns_only_requesting_users_configs(repo_and_session):
    repo, session = repo_and_session
    session.add_all(
        [
            LLMProviderConfig(user_id="user-1", provider="openai", api_key="u1-openai", default_model="gpt-4o-mini", is_active=True),
            LLMProviderConfig(user_id="user-1", provider="xai", api_key="u1-xai", default_model="grok-3-mini", is_active=False),
            LLMProviderConfig(user_id="user-2", provider="openai", api_key="u2-openai", default_model="gpt-4o-mini", is_active=True),
        ]
    )
    await session.commit()

    configs = await repo.list_by_user("user-1")

    assert {(config.user_id, config.provider) for config in configs} == {
        ("user-1", "openai"),
        ("user-1", "xai"),
    }


@pytest.mark.asyncio
async def test_upsert_creates_new_config_for_user_and_provider(repo_and_session):
    repo, _session = repo_and_session

    config = await repo.upsert_by_user_and_provider(
        "user-1",
        "openai",
        api_key="created-key",
        is_active=True,
        default_model="gpt-4o-mini",
    )

    assert config.user_id == "user-1"
    assert config.provider == "openai"
    assert config.api_key == "created-key"
    assert config.is_active is True


@pytest.mark.asyncio
async def test_upsert_updates_existing_config_for_same_user_and_provider(repo_and_session):
    repo, session = repo_and_session
    existing = LLMProviderConfig(
        user_id="user-1",
        provider="openai",
        api_key="old-key",
        default_model="gpt-4o-mini",
        is_active=False,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    session.add(existing)
    await session.commit()

    updated = await repo.upsert_by_user_and_provider(
        "user-1",
        "openai",
        api_key="new-key",
        is_active=True,
        default_model="gpt-4o-mini",
    )

    assert updated.id == existing.id
    assert updated.api_key == "new-key"
    assert updated.is_active is True


@pytest.mark.asyncio
async def test_upsert_for_one_user_does_not_overwrite_another_users_config(repo_and_session):
    repo, session = repo_and_session
    other_users = LLMProviderConfig(
        user_id="user-2",
        provider="openai",
        api_key="user-2-key",
        default_model="gpt-4o-mini",
        is_active=True,
    )
    session.add(other_users)
    await session.commit()

    created = await repo.upsert_by_user_and_provider(
        "user-1",
        "openai",
        api_key="user-1-key",
        is_active=False,
        default_model="gpt-4o-mini",
    )

    user_2 = await repo.get_by_provider("user-2", "openai")

    assert created.user_id == "user-1"
    assert created.api_key == "user-1-key"
    assert user_2 is not None
    assert user_2.api_key == "user-2-key"


@pytest.mark.asyncio
async def test_setting_one_config_active_deactivates_same_users_other_active_config(repo_and_session):
    repo, session = repo_and_session
    session.add_all(
        [
            LLMProviderConfig(user_id="user-1", provider="openai", api_key="openai-key", default_model="gpt-4o-mini", is_active=True),
            LLMProviderConfig(user_id="user-1", provider="xai", api_key="xai-key", default_model="grok-3-mini", is_active=False),
            LLMProviderConfig(user_id="user-2", provider="openai", api_key="user-2-key", default_model="gpt-4o-mini", is_active=True),
        ]
    )
    await session.commit()

    updated = await repo.upsert_by_user_and_provider(
        "user-1",
        "xai",
        api_key="xai-key-updated",
        is_active=True,
        default_model="grok-3-mini",
    )

    user_1_openai = await repo.get_by_provider("user-1", "openai")
    user_1_xai = await repo.get_by_provider("user-1", "xai")
    user_2_openai = await repo.get_by_provider("user-2", "openai")

    assert updated.provider == "xai"
    assert user_1_openai is not None
    assert user_1_openai.is_active is False
    assert user_1_xai is not None
    assert user_1_xai.is_active is True
    assert user_2_openai is not None
    assert user_2_openai.is_active is True
