from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.llm_provider_config import LLMProviderConfigRepository
from app.gateway.models import LLMProviderConfig

logger = logging.getLogger(__name__)


class SQLAlchemyLLMProviderConfigRepository(LLMProviderConfigRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get_active(self, user_id: str) -> LLMProviderConfig | None:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.user_id == user_id)
            .where(LLMProviderConfig.is_active.is_(True))
            .order_by(LLMProviderConfig.updated_at.desc(), LLMProviderConfig.created_at.desc())
            .limit(1)
        )
        config = result.scalar_one_or_none()
        logger.info(
            "remediation_provider_config_lookup",
            extra={
                "lookup_mode": "active",
                "user_id": user_id,
                "config_found": config is not None,
                "provider": str(config.provider) if config is not None else None,
                "default_model": getattr(config, "default_model", None) if config is not None else None,
                "api_key_present": bool(getattr(config, "api_key", None)) if config is not None else False,
            },
        )
        return config

    async def get_by_provider(self, user_id: str, provider: str) -> LLMProviderConfig | None:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.user_id == user_id)
            .where(LLMProviderConfig.provider == provider)
            .limit(1)
        )
        config = result.scalar_one_or_none()
        logger.info(
            "remediation_provider_config_lookup",
            extra={
                "lookup_mode": "by_provider",
                "user_id": user_id,
                "requested_provider": provider,
                "config_found": config is not None,
                "provider": str(config.provider) if config is not None else None,
                "default_model": getattr(config, "default_model", None) if config is not None else None,
                "api_key_present": bool(getattr(config, "api_key", None)) if config is not None else False,
            },
        )
        return config
