from __future__ import annotations

import logging

from datetime import datetime

from sqlalchemy import select, update
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
        any_config_result = await self._session.execute(
            select(LLMProviderConfig.id)
            .where(LLMProviderConfig.user_id == user_id)
            .limit(1)
        )
        has_any_config = any_config_result.scalar_one_or_none() is not None
        logger.info(
            "remediation_provider_config_lookup",
            extra={
                "lookup_mode": "active",
                "user_id": user_id,
                "config_found": config is not None,
                "has_any_config": has_any_config,
                "inactive_configs_present": has_any_config and config is None,
                "provider": str(config.provider) if config is not None else None,
                "default_model": getattr(config, "default_model", None) if config is not None else None,
                "api_key_present": bool(getattr(config, "api_key", None)) if config is not None else False,
                "config_is_active": bool(getattr(config, "is_active", False)) if config is not None else None,
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
                "config_is_active": bool(getattr(config, "is_active", False)) if config is not None else None,
            },
        )
        return config

    async def list_by_user(self, user_id: str) -> list[LLMProviderConfig]:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.user_id == user_id)
            .order_by(LLMProviderConfig.updated_at.desc(), LLMProviderConfig.created_at.desc())
        )
        configs = list(result.scalars().all())
        logger.info(
            "remediation_provider_config_lookup",
            extra={
                "lookup_mode": "list_by_user",
                "user_id": user_id,
                "config_count": len(configs),
            },
        )
        return configs

    async def upsert_by_user_and_provider(
        self,
        user_id: str,
        provider: str,
        *,
        api_key: str,
        is_active: bool,
        default_model: str | None = None,
    ) -> LLMProviderConfig:
        result = await self._session.execute(
            select(LLMProviderConfig)
            .where(LLMProviderConfig.user_id == user_id)
            .where(LLMProviderConfig.provider == provider)
            .limit(1)
        )
        config = result.scalar_one_or_none()

        if is_active:
            await self._session.execute(
                update(LLMProviderConfig)
                .where(LLMProviderConfig.user_id == user_id)
                .where(LLMProviderConfig.provider != provider)
                .values(is_active=False, updated_at=datetime.utcnow())
            )

        if config is None:
            config = LLMProviderConfig(
                user_id=user_id,
                provider=provider,
                api_key=api_key,
                default_model=default_model,
                is_active=is_active,
            )
            self._session.add(config)
        else:
            config.api_key = api_key
            config.default_model = default_model
            config.is_active = is_active
            config.updated_at = datetime.utcnow()

        await self._session.commit()
        await self._session.refresh(config)
        logger.info(
            "remediation_provider_config_upsert",
            extra={
                "user_id": user_id,
                "provider": provider,
                "is_active": is_active,
                "default_model": default_model,
                "api_key_present": bool(api_key.strip()),
            },
        )
        return config
