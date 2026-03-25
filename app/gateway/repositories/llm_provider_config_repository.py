from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.llm_provider_config import LLMProviderConfigRepository
from app.gateway.models import LLMProviderConfig


class SQLAlchemyLLMProviderConfigRepository(LLMProviderConfigRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get_active(self) -> LLMProviderConfig | None:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.is_active.is_(True))
            .order_by(LLMProviderConfig.updated_at.desc(), LLMProviderConfig.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_by_provider(self, provider: str) -> LLMProviderConfig | None:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.provider == provider)
            .limit(1)
        )
        return result.scalar_one_or_none()
