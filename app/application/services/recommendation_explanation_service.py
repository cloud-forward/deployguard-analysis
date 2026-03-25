from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

from fastapi import HTTPException

from app.application.llm.interfaces import (
    ExplanationProvider,
    RecommendationExplanationPrompt,
)
from app.models.schemas import (
    RecommendationExplanationRequest,
    RecommendationExplanationResponse,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationDetailResponse,
)

logger = logging.getLogger(__name__)

OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
XAI_DEFAULT_MODEL = "grok-3-mini"
PROVIDER_DEFAULT_MODELS = {
    "openai": OPENAI_DEFAULT_MODEL,
    "xai": XAI_DEFAULT_MODEL,
}


@dataclass(frozen=True)
class EligibilityResult:
    explainable: bool
    fallback_reason: str | None = None


class RecommendationExplanationService:
    def __init__(
        self,
        attack_graph_service,
        provider_config_repository,
        providers: dict[str, ExplanationProvider],
    ) -> None:
        self._attack_graph_service = attack_graph_service
        self._provider_configs = provider_config_repository
        self._providers = providers

    async def explain_recommendation(
        self,
        *,
        cluster_id: str,
        recommendation_id: str,
        user_id: str,
        request: RecommendationExplanationRequest,
    ) -> RecommendationExplanationResponse:
        requested_provider = request.provider.value if request.provider is not None else None
        logger.info(
            "remediation_explanation_request",
            extra={
                "cluster_id": cluster_id,
                "recommendation_id": recommendation_id,
                "user_id": user_id,
                "requested_provider": requested_provider,
                "requested_model": request.model,
            },
        )
        try:
            envelope: RemediationRecommendationDetailEnvelopeResponse = (
                await self._attack_graph_service.get_remediation_recommendation_detail(
                    cluster_id=cluster_id,
                    recommendation_id=recommendation_id,
                )
            )
        except HTTPException as exc:
            logger.warning(
                "remediation_explanation_request",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation_id,
                    "user_id": user_id,
                    "stage": "detail_lookup",
                    "exception_type": type(exc).__name__,
                    "error_detail": str(exc.detail),
                    "status_code": exc.status_code,
                },
            )
            if exc.status_code == 404 and exc.detail == "Remediation recommendation not found":
                envelope = RemediationRecommendationDetailEnvelopeResponse(
                    cluster_id=cluster_id,
                    analysis_run_id=None,
                    generated_at=None,
                    recommendation=None,
                )
            else:
                raise
        recommendation = envelope.recommendation
        if recommendation is None:
            logger.info(
                "remediation_explanation_eligibility",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation_id,
                    "user_id": user_id,
                    "eligibility_passed": False,
                    "fallback_reason": "recommendation_not_found",
                    "provider_call_skipped": True,
                },
            )
            fallback_text = "No explanation available because the remediation recommendation was not found."
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation_id,
                explanation_status="no_target",
                used_llm=False,
                base_explanation=fallback_text,
                final_explanation=fallback_text,
                provider=requested_provider,
                model=request.model,
                fallback_reason="recommendation_not_found",
            )

        eligibility = self._check_eligibility(recommendation)
        logger.info(
            "remediation_explanation_eligibility",
            extra={
                "cluster_id": cluster_id,
                "recommendation_id": recommendation.recommendation_id,
                "user_id": user_id,
                "eligibility_passed": eligibility.explainable,
                "fallback_reason": eligibility.fallback_reason,
                "edge_type": recommendation.edge_type,
                "has_fix_description": bool(recommendation.fix_description),
                "has_fix_type": bool(recommendation.fix_type),
                "blocked_path_id_count": len(recommendation.blocked_path_ids or []),
                "blocked_path_index_count": len(recommendation.blocked_path_indices or []),
                "has_covered_risk": recommendation.covered_risk is not None,
                "has_impact_reason": bool(
                    isinstance(recommendation.metadata, dict)
                    and isinstance(recommendation.metadata.get("impact_reason"), str)
                    and recommendation.metadata.get("impact_reason").strip()
                ),
            },
        )
        if not eligibility.explainable:
            fallback_text = "Nothing to explain for this remediation recommendation."
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="not_explainable",
                used_llm=False,
                base_explanation=fallback_text,
                final_explanation=fallback_text,
                provider=requested_provider,
                model=request.model,
                fallback_reason=eligibility.fallback_reason or "missing_minimum_structured_input",
            )

        base_explanation = self._build_base_explanation(recommendation)
        selected_provider_name, selected_model, api_key, provider_fallback_reason = await self._resolve_provider(
            user_id,
            requested_provider,
            request.model,
        )
        if selected_provider_name is None or selected_model is None:
            logger.info(
                "remediation_provider_call_skipped",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "requested_provider": requested_provider,
                    "requested_model": request.model,
                    "resolved_provider": selected_provider_name,
                    "resolved_model": selected_model,
                    "fallback_reason": provider_fallback_reason or "provider_not_configured",
                },
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="base_only",
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=requested_provider,
                model=request.model,
                fallback_reason=provider_fallback_reason or "provider_not_configured",
            )

        provider = self._providers.get(selected_provider_name)
        if provider is None or api_key is None:
            logger.info(
                "remediation_provider_call_skipped",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "requested_provider": requested_provider,
                    "requested_model": request.model,
                    "resolved_provider": selected_provider_name,
                    "resolved_model": selected_model,
                    "provider_adapter_found": provider is not None,
                    "api_key_present": api_key is not None and bool(str(api_key).strip()),
                    "fallback_reason": "provider_not_configured" if provider is None else "api_key_missing",
                },
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="base_only",
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=selected_provider_name,
                model=selected_model,
                fallback_reason="provider_not_configured" if provider is None else "api_key_missing",
            )

        prompt = RecommendationExplanationPrompt(
            target_type="remediation_recommendation",
            recommendation_id=recommendation.recommendation_id,
            base_explanation=base_explanation,
            structured_input=self._structured_input(recommendation),
            provider=selected_provider_name,
            model=selected_model,
            api_key=api_key,
        )

        try:
            logger.info(
                "remediation_provider_call_started",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "provider": selected_provider_name,
                    "model": selected_model,
                },
            )
            result = await provider.generate_explanation(prompt)
        except Exception as exc:
            logger.exception(
                "remediation_provider_call_failed",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "provider": selected_provider_name,
                    "model": selected_model,
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="llm_failed_fallback",
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=selected_provider_name,
                model=selected_model,
                fallback_reason="provider_call_failed",
            )

        logger.info(
            "remediation_provider_call_completed",
            extra={
                "cluster_id": cluster_id,
                "recommendation_id": recommendation.recommendation_id,
                "user_id": user_id,
                "provider": result.provider,
                "model": result.model,
                "used_llm": True,
            },
        )
        return RecommendationExplanationResponse(
            cluster_id=cluster_id,
            recommendation_id=recommendation.recommendation_id,
            explanation_status="llm_generated",
            used_llm=True,
            base_explanation=base_explanation,
            final_explanation=result.text,
            provider=result.provider,
            model=result.model,
            fallback_reason=None,
        )

    async def _resolve_provider(
        self,
        user_id: str,
        requested_provider: str | None,
        requested_model: str | None,
    ) -> tuple[str | None, str | None, str | None, str | None]:
        config = (
            await self._provider_configs.get_by_provider(user_id, requested_provider)
            if requested_provider
            else await self._provider_configs.get_active(user_id)
        )
        logger.info(
            "remediation_provider_config_lookup",
            extra={
                "user_id": user_id,
                "requested_provider": requested_provider,
                "requested_model": requested_model,
                "config_found": config is not None,
                "resolved_provider": str(config.provider) if config is not None else None,
                "resolved_default_model": getattr(config, "default_model", None) if config is not None else None,
                "api_key_present": bool(getattr(config, "api_key", None)) if config is not None else False,
                "lookup_mode": "by_provider" if requested_provider else "active",
            },
        )
        if config is None:
            return None, None, None, "provider_not_configured"

        provider_name = str(config.provider)
        if not getattr(config, "api_key", None):
            return provider_name, requested_model or getattr(config, "default_model", None), None, "api_key_missing"

        model = requested_model or getattr(config, "default_model", None) or PROVIDER_DEFAULT_MODELS.get(provider_name)
        if not model:
            return provider_name, None, str(config.api_key), "provider_not_configured"

        return provider_name, model, str(config.api_key), None

    @staticmethod
    def _check_eligibility(recommendation: RemediationRecommendationDetailResponse) -> EligibilityResult:
        if not recommendation.recommendation_id:
            return EligibilityResult(False, "missing_minimum_structured_input")
        if not isinstance(recommendation.edge_type, str) or not recommendation.edge_type.strip():
            return EligibilityResult(False, "missing_minimum_structured_input")

        has_action = any(
            isinstance(value, str) and value.strip()
            for value in (recommendation.fix_description, recommendation.fix_type)
        )
        if not has_action:
            return EligibilityResult(False, "missing_minimum_structured_input")

        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        impact_reason = metadata.get("impact_reason")
        has_impact_signal = any(
            (
                bool(recommendation.blocked_path_ids),
                bool(recommendation.blocked_path_indices),
                recommendation.covered_risk is not None,
                isinstance(impact_reason, str) and bool(impact_reason.strip()),
            )
        )
        if not has_impact_signal:
            return EligibilityResult(False, "missing_minimum_structured_input")

        return EligibilityResult(True, None)

    @staticmethod
    def _build_base_explanation(recommendation: RemediationRecommendationDetailResponse) -> str:
        source_ref = f"`{recommendation.edge_source}`" if recommendation.edge_source else "the source object"
        target_ref = f"`{recommendation.edge_target}`" if recommendation.edge_target else "the target object"
        action = recommendation.fix_description
        if not action and recommendation.fix_type:
            action = recommendation.fix_type.replace("_", " ")
        if not action:
            action = "apply the recommended change"

        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        impact_reason = metadata.get("impact_reason")
        if not isinstance(impact_reason, str) or not impact_reason.strip():
            impact_reason = "this relationship keeps the risky path open"

        impact_parts: list[str] = []
        if recommendation.blocked_path_ids:
            path_count = len(recommendation.blocked_path_ids)
            impact_parts.append(f"it is expected to block {path_count} risky path{'s' if path_count != 1 else ''}")
        elif recommendation.blocked_path_indices:
            path_count = len(recommendation.blocked_path_indices)
            impact_parts.append(f"it is expected to block {path_count} ranked path{'s' if path_count != 1 else ''}")

        if recommendation.covered_risk is not None:
            impact_parts.append(f"the indicated raw risk reduction is {recommendation.covered_risk:.2f}")
        if recommendation.cumulative_risk_reduction is not None:
            impact_parts.append(
                f"the cumulative reduction ratio at this rank is {recommendation.cumulative_risk_reduction:.2f}"
            )
        impact_sentence = (
            " Impact: " + "; ".join(impact_parts) + "."
            if impact_parts
            else ""
        )

        return (
            f"Recommended change for edge {source_ref} -> {target_ref}: {action}. "
            f"This recommendation matters because {impact_reason}.{impact_sentence}"
        )

    @staticmethod
    def _structured_input(recommendation: RemediationRecommendationDetailResponse) -> dict[str, Any]:
        return {
            "recommendation_id": recommendation.recommendation_id,
            "recommendation_rank": recommendation.recommendation_rank,
            "edge_source": recommendation.edge_source,
            "edge_target": recommendation.edge_target,
            "edge_type": recommendation.edge_type,
            "fix_type": recommendation.fix_type,
            "fix_description": recommendation.fix_description,
            "blocked_path_ids": list(recommendation.blocked_path_ids or []),
            "blocked_path_indices": list(recommendation.blocked_path_indices or []),
            "fix_cost": recommendation.fix_cost,
            "edge_score": recommendation.edge_score,
            "covered_risk": recommendation.covered_risk,
            "cumulative_risk_reduction": recommendation.cumulative_risk_reduction,
            "metadata": dict(recommendation.metadata or {}),
        }
