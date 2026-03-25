from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import HTTPException

from app.application.services.recommendation_explanation_service import RecommendationExplanationService
from app.models.schemas import (
    RecommendationExplanationRequest,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationDetailResponse,
)


@dataclass
class FakeProviderConfig:
    provider: str
    api_key: str | None
    default_model: str | None = None
    is_active: bool = False


class FakeProviderConfigRepository:
    def __init__(self, active=None, by_provider=None):
        self._active = active
        self._by_provider = by_provider or {}

    async def get_active(self):
        return self._active

    async def get_by_provider(self, provider: str):
        return self._by_provider.get(provider)


class FakeProvider:
    provider_name = "fake"

    def __init__(self, *, text: str = "rewritten", error: Exception | None = None):
        self.text = text
        self.error = error
        self.calls = []

    async def generate_explanation(self, prompt):
        self.calls.append(prompt)
        if self.error is not None:
            raise self.error

        class Result:
            def __init__(self, text):
                self.text = text
                self.provider = prompt.provider
                self.model = prompt.model

        return Result(self.text)


class FakeAttackGraphService:
    def __init__(self, envelope):
        self.envelope = envelope
        self.calls = []

    async def get_remediation_recommendation_detail(self, cluster_id: str, recommendation_id: str):
        self.calls.append((cluster_id, recommendation_id))
        return self.envelope


class RaisingAttackGraphService:
    def __init__(self, exc):
        self.exc = exc
        self.calls = []

    async def get_remediation_recommendation_detail(self, cluster_id: str, recommendation_id: str):
        self.calls.append((cluster_id, recommendation_id))
        raise self.exc


def make_recommendation(**overrides):
    base = RemediationRecommendationDetailResponse(
        recommendation_id="rotate-credentials-1",
        recommendation_rank=0,
        edge_source="secret:prod:db-creds",
        edge_target="rds:prod-db",
        edge_type="secret_contains_credentials",
        fix_type="rotate_credentials",
        fix_description="Rotate exposed database credentials.",
        blocked_path_ids=["path-db"],
        blocked_path_indices=[4],
        fix_cost=1.3,
        edge_score=0.9,
        covered_risk=0.9,
        cumulative_risk_reduction=0.9,
        metadata={"impact_reason": "this secret contains reusable credentials"},
    )
    return base.model_copy(update=overrides)


@pytest.mark.asyncio
async def test_recommendation_missing_returns_no_target_and_skips_provider():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=None,
        )
    )
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="missing-rec",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "no_target"
    assert result.used_llm is False
    assert result.fallback_reason == "recommendation_not_found"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_missing_recommendation_http_404_is_normalized_to_no_target_and_skips_provider():
    attack_service = RaisingAttackGraphService(HTTPException(status_code=404, detail="Remediation recommendation not found"))
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="missing-rec",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "no_target"
    assert result.used_llm is False
    assert result.provider is None
    assert result.model is None
    assert result.fallback_reason == "recommendation_not_found"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_minimum_explainable_input_missing_returns_not_explainable_and_skips_provider():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(
                edge_type="",
                fix_description=None,
                fix_type=None,
                blocked_path_ids=[],
                blocked_path_indices=[],
                covered_risk=None,
                metadata={},
            ),
        )
    )
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "not_explainable"
    assert result.used_llm is False
    assert result.fallback_reason == "missing_minimum_structured_input"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_explainable_recommendation_with_missing_provider_config_returns_base_only():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(active=None),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "base_only"
    assert result.used_llm is False
    assert result.fallback_reason == "provider_not_configured"
    assert result.final_explanation == result.base_explanation
    assert provider.calls == []


@pytest.mark.asyncio
async def test_explainable_recommendation_with_missing_api_key_returns_base_only_and_skips_provider():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active=FakeProviderConfig(provider="openai", api_key="", default_model="gpt-4o-mini", is_active=True)
        ),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "base_only"
    assert result.used_llm is False
    assert result.fallback_reason == "api_key_missing"
    assert result.final_explanation == result.base_explanation
    assert provider.calls == []


@pytest.mark.asyncio
async def test_provider_success_returns_llm_generated():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider(text="LLM rewritten explanation.")
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active=FakeProviderConfig(provider="openai", api_key="secret-key", default_model="gpt-4o-mini", is_active=True)
        ),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_generated"
    assert result.used_llm is True
    assert result.final_explanation == "LLM rewritten explanation."
    assert result.provider == "openai"
    assert result.model == "gpt-4o-mini"
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_provider_failure_returns_llm_failed_fallback():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider(error=RuntimeError("boom"))
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active=FakeProviderConfig(provider="openai", api_key="secret-key", default_model="gpt-4o-mini", is_active=True)
        ),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_failed_fallback"
    assert result.used_llm is False
    assert result.final_explanation == result.base_explanation
    assert result.fallback_reason == "provider_call_failed"
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_request_time_provider_and_model_override_is_used_when_saved_config_exists():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider(text="xAI explanation")
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active=FakeProviderConfig(provider="openai", api_key="openai-key", default_model="gpt-4o-mini", is_active=True),
            by_provider={"xai": FakeProviderConfig(provider="xai", api_key="xai-key", default_model="grok-3-mini")},
        ),
        providers={"xai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(provider="xai", model="grok-3-mini"),
    )

    assert result.explanation_status == "llm_generated"
    assert result.provider == "xai"
    assert result.model == "grok-3-mini"
    assert len(provider.calls) == 1
    assert provider.calls[0].provider == "xai"
    assert provider.calls[0].model == "grok-3-mini"
    assert provider.calls[0].api_key == "xai-key"


@pytest.mark.asyncio
async def test_provider_override_with_no_saved_config_returns_base_only_and_skips_provider():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active=FakeProviderConfig(provider="openai", api_key="openai-key", default_model="gpt-4o-mini", is_active=True),
            by_provider={},
        ),
        providers={"xai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        request=RecommendationExplanationRequest(provider="xai", model="grok-3-mini"),
    )

    assert result.explanation_status == "base_only"
    assert result.used_llm is False
    assert result.fallback_reason == "provider_not_configured"
    assert provider.calls == []
