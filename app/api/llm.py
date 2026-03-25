from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.application.di import get_llm_provider_config_service
from app.application.services.llm_provider_config_service import LLMProviderConfigService
from app.models.schemas import (
    ExplanationProviderName,
    LLMProviderConfigListResponse,
    LLMProviderConfigResponse,
    LLMProviderConfigUpsertRequest,
    UserSummaryResponse,
)

router = APIRouter(prefix="/api/v1/llm", tags=["LLM"])


@router.get(
    "/provider-configs",
    response_model=LLMProviderConfigListResponse,
    summary="LLM provider config list",
)
async def list_llm_provider_configs(
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: LLMProviderConfigService = Depends(get_llm_provider_config_service),
):
    return await service.list_configs(user_id=current_user.id)


@router.put(
    "/provider-configs/{provider}",
    response_model=LLMProviderConfigResponse,
    summary="Create or update an LLM provider config",
)
async def upsert_llm_provider_config(
    provider: ExplanationProviderName,
    request: LLMProviderConfigUpsertRequest,
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: LLMProviderConfigService = Depends(get_llm_provider_config_service),
):
    return await service.upsert_config(user_id=current_user.id, provider=provider, request=request)
