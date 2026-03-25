from __future__ import annotations

import logging

from app.models.schemas import (
    ExplanationProviderName,
    LLMProviderConfigListResponse,
    LLMProviderConfigResponse,
    LLMProviderConfigUpsertRequest,
)

logger = logging.getLogger(__name__)


class LLMProviderConfigService:
    def __init__(self, provider_config_repository) -> None:
        self._provider_configs = provider_config_repository

    async def list_configs(self, user_id: str) -> LLMProviderConfigListResponse:
        configs = await self._provider_configs.list_by_user(user_id)
        logger.info(
            "llm_provider_config_list",
            extra={
                "user_id": user_id,
                "config_count": len(configs),
            },
        )
        return LLMProviderConfigListResponse(
            items=[self._to_response(config) for config in configs],
        )

    async def upsert_config(
        self,
        *,
        user_id: str,
        provider: ExplanationProviderName,
        request: LLMProviderConfigUpsertRequest,
    ) -> LLMProviderConfigResponse:
        logger.info(
            "llm_provider_config_upsert",
            extra={
                "user_id": user_id,
                "provider": provider.value,
                "is_active": request.is_active,
                "default_model": request.default_model,
                "api_key_present": bool(request.api_key.strip()),
            },
        )
        config = await self._provider_configs.upsert_by_user_and_provider(
            user_id,
            provider.value,
            api_key=request.api_key,
            is_active=request.is_active,
            default_model=request.default_model,
        )
        return self._to_response(config)

    @staticmethod
    def _to_response(config) -> LLMProviderConfigResponse:
        return LLMProviderConfigResponse(
            provider=config.provider,
            is_active=config.is_active,
            default_model=config.default_model,
            has_api_key=bool(getattr(config, "api_key", None)),
            created_at=config.created_at,
            updated_at=config.updated_at,
        )
