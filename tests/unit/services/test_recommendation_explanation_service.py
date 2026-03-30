from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import HTTPException

from app.application.llm.interfaces import RecommendationExplanationPrompt
from app.application.llm.providers.openai_explanation_client import OpenAIExplanationClient
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
        self.calls = []

    async def get_active(self, user_id: str):
        self.calls.append(("get_active", user_id))
        if isinstance(self._active, dict):
            return self._active.get(user_id)
        return self._active

    async def get_by_provider(self, user_id: str, provider: str):
        self.calls.append(("get_by_provider", user_id, provider))
        if isinstance(self._by_provider, dict):
            scoped = self._by_provider.get(user_id, {})
            if isinstance(scoped, dict):
                return scoped.get(provider)
        return None


class FakeAnalysisJobsRepository:
    def __init__(self):
        self.success_calls = []
        self.failure_calls = []

    async def save_llm_explanation_success(self, graph_id: str, recommendation_id: str, explanation: str, provider: str, model: str):
        self.success_calls.append(
            {
                "graph_id": graph_id,
                "recommendation_id": recommendation_id,
                "explanation": explanation,
                "provider": provider,
                "model": model,
            }
        )
        return None

    async def save_llm_explanation_failure(self, graph_id: str, recommendation_id: str, error_message: str, provider: str, model: str):
        self.failure_calls.append(
            {
                "graph_id": graph_id,
                "recommendation_id": recommendation_id,
                "error_message": error_message,
                "provider": provider,
                "model": model,
            }
        )
        return None


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
    def __init__(self, envelope, graph_id: str = "graph-1"):
        self.envelope = envelope
        self.graph_id = graph_id
        self.calls = []
        self.graph_calls = []

    async def get_remediation_recommendation_detail(self, cluster_id: str, recommendation_id: str, user_id: str | None = None):
        self.calls.append((cluster_id, recommendation_id, user_id))
        return self.envelope

    async def get_latest_analysis_graph_id(self, cluster_id: str, user_id: str | None = None):
        self.graph_calls.append((cluster_id, user_id))
        return self.graph_id


class RaisingAttackGraphService:
    def __init__(self, exc):
        self.exc = exc
        self.calls = []

    async def get_remediation_recommendation_detail(self, cluster_id: str, recommendation_id: str, user_id: str | None = None):
        self.calls.append((cluster_id, recommendation_id, user_id))
        raise self.exc


def make_recommendation(**overrides):
    base = RemediationRecommendationDetailResponse(
        recommendation_id="rotate-credentials-1",
        recommendation_rank=0,
        edge_source="secret:prod:db-creds",
        edge_target="rds:prod-db",
        edge_type="secret_contains_credentials",
        fix_type="rotate_credentials",
        fix_description="노출된 데이터베이스 자격 증명을 교체합니다.",
        blocked_path_ids=["path-db"],
        blocked_path_indices=[4],
        fix_cost=1.3,
        edge_score=0.9,
        covered_risk=0.9,
        cumulative_risk_reduction=0.9,
        metadata={"impact_reason": "이 secret에 재사용 가능한 자격 증명이 포함되어 있기 때문입니다"},
    )
    return base.model_copy(update=overrides)


def make_service_account_recommendation(**overrides):
    base = RemediationRecommendationDetailResponse(
        recommendation_id="change-sa-1",
        recommendation_rank=1,
        edge_source="pod:prod:api",
        edge_target="serviceaccount:prod:api-sa",
        edge_type="pod_uses_service_account",
        fix_type="change_service_account",
        fix_description="Change pod:prod:api -> serviceaccount:prod:api-sa: workload의 service account를 변경합니다.",
        blocked_path_ids=["path-sa-1", "path-sa-2"],
        blocked_path_indices=[1, 2],
        fix_cost=1.6,
        edge_score=0.8,
        covered_risk=1.53,
        cumulative_risk_reduction=0.61,
        metadata={
            "impact_reason": "이 workload가 path 상의 service account 권한을 상속받기 때문입니다",
            "base_action": "workload의 service account를 변경",
        },
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
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="missing-rec",
        user_id="user-1",
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
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="missing-rec",
        user_id="user-1",
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
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "not_explainable"
    assert result.used_llm is False
    assert result.fallback_reason == "missing_minimum_structured_input"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_explainable_recommendation_with_missing_active_provider_config_returns_specific_skip_status():
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
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "no_active_provider_config"
    assert result.used_llm is False
    assert result.fallback_reason == "no_active_provider_config"
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
            active={"user-1": FakeProviderConfig(provider="openai", api_key="", default_model="gpt-4o-mini", is_active=True)}
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "api_key_missing"
    assert result.used_llm is False
    assert result.fallback_reason == "api_key_missing"
    assert result.final_explanation == result.base_explanation
    assert provider.calls == []


@pytest.mark.asyncio
async def test_explainable_recommendation_with_unresolved_model_returns_specific_skip_status():
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
            active={"user-1": FakeProviderConfig(provider="custom-provider", api_key="secret-key", default_model=None, is_active=True)}
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "model_unresolved"
    assert result.used_llm is False
    assert result.fallback_reason == "model_unresolved"
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
    jobs_repo = FakeAnalysisJobsRepository()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active={"user-1": FakeProviderConfig(provider="openai", api_key="secret-key", default_model="gpt-4o-mini", is_active=True)}
        ),
        analysis_jobs_repository=jobs_repo,
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_generated"
    assert result.used_llm is True
    assert result.final_explanation == "LLM rewritten explanation."
    assert result.provider == "openai"
    assert result.model == "gpt-4o-mini"
    assert len(provider.calls) == 1
    assert provider.calls[0].structured_input["derived_context"]["recommendation_intent"] == "credential containment"
    assert provider.calls[0].structured_input["derived_context"]["security_effect"] is not None
    assert provider.calls[0].structured_input["derived_context"]["path_interruption"] == "secret -> credential reuse 경로"
    assert provider.calls[0].base_explanation.count("중요한 이유:") == 1
    assert provider.calls[0].base_explanation.count("예상 효과:") == 1
    assert provider.calls[0].base_explanation.startswith("권장 변경:")
    assert attack_service.calls == [("cluster-1", "rotate-credentials-1", "user-1")]
    assert attack_service.graph_calls == [("cluster-1", "user-1")]
    assert jobs_repo.success_calls == [
        {
            "graph_id": "graph-1",
            "recommendation_id": "rotate-credentials-1",
            "explanation": "LLM rewritten explanation.",
            "provider": "openai",
            "model": "gpt-4o-mini",
        }
    ]
    assert jobs_repo.failure_calls == []


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
    jobs_repo = FakeAnalysisJobsRepository()
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active={"user-1": FakeProviderConfig(provider="openai", api_key="secret-key", default_model="gpt-4o-mini", is_active=True)}
        ),
        analysis_jobs_repository=jobs_repo,
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_failed_fallback"
    assert result.used_llm is False
    assert result.final_explanation == result.base_explanation
    assert result.fallback_reason == "provider_call_failed"
    assert len(provider.calls) == 1
    assert attack_service.calls == [("cluster-1", "rotate-credentials-1", "user-1")]
    assert attack_service.graph_calls == [("cluster-1", "user-1")]
    assert jobs_repo.success_calls == []
    assert jobs_repo.failure_calls == [
        {
            "graph_id": "graph-1",
            "recommendation_id": "rotate-credentials-1",
            "error_message": "LLM generation failed",
            "provider": "openai",
            "model": "gpt-4o-mini",
        }
    ]


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
            active={"user-1": FakeProviderConfig(provider="openai", api_key="openai-key", default_model="gpt-4o-mini", is_active=True)},
            by_provider={"user-1": {"xai": FakeProviderConfig(provider="xai", api_key="xai-key", default_model="grok-3-mini")}},
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"xai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
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
async def test_provider_override_with_no_saved_config_returns_specific_skip_status():
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
            active={"user-1": FakeProviderConfig(provider="openai", api_key="openai-key", default_model="gpt-4o-mini", is_active=True)},
            by_provider={},
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"xai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(provider="xai", model="grok-3-mini"),
    )

    assert result.explanation_status == "provider_config_not_found"
    assert result.used_llm is False
    assert result.fallback_reason == "provider_config_not_found"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_missing_provider_adapter_returns_specific_skip_status():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=FakeProviderConfigRepository(
            active={"user-1": FakeProviderConfig(provider="openai", api_key="secret-key", default_model="gpt-4o-mini", is_active=True)}
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "provider_adapter_missing"
    assert result.used_llm is False
    assert result.fallback_reason == "provider_adapter_missing"
    assert result.final_explanation == result.base_explanation


@pytest.mark.asyncio
async def test_active_provider_config_lookup_is_scoped_by_user_id():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider(text="LLM rewritten explanation.")
    repo = FakeProviderConfigRepository(
        active={
            "user-1": FakeProviderConfig(provider="openai", api_key="user-1-key", default_model="gpt-4o-mini", is_active=True),
            "user-2": FakeProviderConfig(provider="openai", api_key="user-2-key", default_model="gpt-4o-mini", is_active=True),
        }
    )
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=repo,
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_generated"
    assert provider.calls[0].api_key == "user-1-key"
    assert ("get_active", "user-1") in repo.calls


@pytest.mark.asyncio
async def test_provider_override_lookup_is_scoped_by_user_id():
    attack_service = FakeAttackGraphService(
        RemediationRecommendationDetailEnvelopeResponse(
            cluster_id="cluster-1",
            analysis_run_id="analysis-1",
            generated_at=None,
            recommendation=make_recommendation(),
        )
    )
    provider = FakeProvider(text="xAI explanation")
    repo = FakeProviderConfigRepository(
        by_provider={
            "user-1": {"xai": FakeProviderConfig(provider="xai", api_key="user-1-xai-key", default_model="grok-3-mini")},
            "user-2": {"xai": FakeProviderConfig(provider="xai", api_key="user-2-xai-key", default_model="grok-3-mini")},
        }
    )
    service = RecommendationExplanationService(
        attack_graph_service=attack_service,
        provider_config_repository=repo,
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"xai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-1",
        request=RecommendationExplanationRequest(provider="xai", model="grok-3-mini"),
    )

    assert result.explanation_status == "llm_generated"
    assert provider.calls[0].api_key == "user-1-xai-key"
    assert ("get_by_provider", "user-1", "xai") in repo.calls


@pytest.mark.asyncio
async def test_explanation_service_uses_requesting_users_config_not_another_users():
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
            active={
                "user-1": FakeProviderConfig(provider="openai", api_key="user-1-key", default_model="gpt-4o-mini", is_active=True),
                "user-2": FakeProviderConfig(provider="openai", api_key="user-2-key", default_model="gpt-4o-mini", is_active=True),
            }
        ),
        analysis_jobs_repository=FakeAnalysisJobsRepository(),
        providers={"openai": provider},
    )

    result = await service.explain_recommendation(
        cluster_id="cluster-1",
        recommendation_id="rotate-credentials-1",
        user_id="user-2",
        request=RecommendationExplanationRequest(),
    )

    assert result.explanation_status == "llm_generated"
    assert provider.calls[0].api_key == "user-2-key"


def test_build_base_explanation_is_compact_and_non_repetitive():
    recommendation = make_recommendation()

    explanation = RecommendationExplanationService._build_base_explanation(recommendation)

    assert explanation.startswith("권장 변경:")
    assert explanation.count("권장 변경:") == 1
    assert explanation.count("중요한 이유:") == 1
    assert explanation.count("예상 효과:") == 1
    assert "Raw risk를 0.90만큼 줄입니다" in explanation
    assert "에 대한 권장 변경" not in explanation
    assert "edge " not in explanation
    assert "\n" in explanation


def test_build_base_explanation_uses_clean_action_not_legacy_fix_description():
    recommendation = make_service_account_recommendation()

    explanation = RecommendationExplanationService._build_base_explanation(recommendation)

    assert explanation == (
        "권장 변경: workload의 service account를 변경.\n"
        "중요한 이유: 이 workload가 path 상의 service account 권한을 상속받기 때문입니다.\n"
        "예상 효과: risky path 2개를 차단합니다, Raw risk를 1.53만큼 줄입니다, cumulative reduction ratio는 0.61입니다."
    )


def test_derived_context_is_recommendation_specific_for_service_account_change():
    recommendation = make_service_account_recommendation()

    derived = RecommendationExplanationService._derive_recommendation_context(recommendation)

    assert derived["recommendation_intent"] == "privilege reduction"
    assert derived["edge_meaning"] == "이 workload가 현재 referenced service account를 통해 path 상의 권한을 상속받고 있는 cut point입니다."
    assert derived["security_effect"] == "service account를 바꾸면 이 workload에 연결된 inherited permission path를 직접 끊을 수 있습니다."
    assert derived["operational_caution"] == "교체할 service account가 workload에 필요한 Kubernetes/API access는 유지하는지 확인해야 합니다."
    assert derived["path_interruption"] == "workload -> service account 권한 상속 경로"


@pytest.mark.asyncio
async def test_openai_prompt_includes_stronger_anti_generic_guidance(monkeypatch):
    captured: dict[str, object] = {}

    class DummyResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "generated"}}]}

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return DummyResponse()

    monkeypatch.setattr("app.application.llm.providers.openai_explanation_client.httpx.AsyncClient", DummyAsyncClient)

    client = OpenAIExplanationClient()
    prompt = RecommendationExplanationPrompt(
        target_type="remediation_recommendation",
        recommendation_id="change-sa-1",
        base_explanation=RecommendationExplanationService._build_base_explanation(make_service_account_recommendation()),
        structured_input=RecommendationExplanationService._structured_input(make_service_account_recommendation()),
        provider="openai",
        model="gpt-4o-mini",
        api_key="secret",
    )

    result = await client.generate_explanation(prompt)

    assert result.text == "generated"
    payload = captured["json"]
    assert isinstance(payload, dict)
    messages = payload["messages"]
    system_prompt = messages[0]["content"]
    user_prompt = messages[1]["content"]
    assert "Do not closely paraphrase the base explanation" in system_prompt
    assert "Explain why this exact edge is the right cut point" in system_prompt
    assert "Avoid generic endings" in system_prompt
    assert "Interpreted context:" in user_prompt
    assert "generic한 마무리 문장" in user_prompt
