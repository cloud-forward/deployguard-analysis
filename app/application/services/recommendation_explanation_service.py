from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

from fastapi import HTTPException

from app.application.llm.interfaces import (
    ExplanationProvider,
    RecommendationExplanationPrompt,
)
from app.core.remediation_optimizer import FIX_TYPE_DISPLAY_MAP_KO
from app.models.schemas import (
    RecommendationExplanationRequest,
    RecommendationExplanationResponse,
    RemediationRecommendationDetailEnvelopeResponse,
    RemediationRecommendationDetailResponse,
)

logger = logging.getLogger(__name__)

OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
XAI_DEFAULT_MODEL = "grok-3-mini"
GENERIC_LLM_FAILURE_MESSAGE = "LLM generation failed"
PROVIDER_DEFAULT_MODELS = {
    "openai": OPENAI_DEFAULT_MODEL,
    "xai": XAI_DEFAULT_MODEL,
}


@dataclass(frozen=True)
class EligibilityResult:
    explainable: bool
    fallback_reason: str | None = None


@dataclass(frozen=True)
class ProviderResolutionResult:
    provider_name: str | None
    model: str | None
    api_key: str | None
    explanation_status: str
    fallback_reason: str | None
    config_found: bool
    config_is_active: bool | None
    lookup_mode: str


class RecommendationExplanationService:
    def __init__(
        self,
        attack_graph_service,
        provider_config_repository,
        analysis_jobs_repository,
        providers: dict[str, ExplanationProvider],
    ) -> None:
        self._attack_graph_service = attack_graph_service
        self._provider_configs = provider_config_repository
        self._analysis_jobs = analysis_jobs_repository
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
                    user_id=user_id,
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
            self._log_skip(
                "remediation_explanation_eligibility",
                cluster_id=cluster_id,
                recommendation_id=recommendation_id,
                user_id=user_id,
                skip_stage="detail_lookup",
                explanation_status="no_target",
                fallback_reason="recommendation_not_found",
                provider_call_attempted=False,
            )
            fallback_text = "설명할 recommendation이 없습니다."
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
            self._log_skip(
                "remediation_explanation_eligibility",
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                user_id=user_id,
                skip_stage="eligibility",
                explanation_status="not_explainable",
                fallback_reason=eligibility.fallback_reason or "missing_minimum_structured_input",
                provider_call_attempted=False,
            )
            fallback_text = "이 recommendation은 설명할 정보가 부족합니다."
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
        graph_id = await self._attack_graph_service.get_latest_analysis_graph_id(
            cluster_id,
            user_id=user_id,
        )
        resolution = await self._resolve_provider(
            user_id,
            requested_provider,
            request.model,
        )
        if resolution.explanation_status != "resolved":
            self._log_skip(
                "remediation_provider_call_skipped",
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                user_id=user_id,
                skip_stage="provider_resolution",
                explanation_status=resolution.explanation_status,
                fallback_reason=resolution.fallback_reason,
                resolved_provider=resolution.provider_name,
                resolved_model=resolution.model,
                config_found=resolution.config_found,
                config_is_active=resolution.config_is_active,
                provider_call_attempted=False,
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status=resolution.explanation_status,
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=requested_provider,
                model=request.model,
                fallback_reason=resolution.fallback_reason,
            )

        provider = self._providers.get(resolution.provider_name)
        if provider is None:
            self._log_skip(
                "remediation_provider_call_skipped",
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                user_id=user_id,
                skip_stage="provider_adapter",
                explanation_status="provider_adapter_missing",
                fallback_reason="provider_adapter_missing",
                resolved_provider=resolution.provider_name,
                resolved_model=resolution.model,
                config_found=resolution.config_found,
                config_is_active=resolution.config_is_active,
                provider_call_attempted=False,
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="provider_adapter_missing",
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=resolution.provider_name,
                model=resolution.model,
                fallback_reason="provider_adapter_missing",
            )

        prompt = RecommendationExplanationPrompt(
            target_type="remediation_recommendation",
            recommendation_id=recommendation.recommendation_id,
            base_explanation=base_explanation,
            structured_input=self._structured_input(recommendation),
            provider=resolution.provider_name,
            model=resolution.model,
            api_key=resolution.api_key,
        )

        try:
            logger.info(
                "remediation_provider_call_started",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "provider": resolution.provider_name,
                    "model": resolution.model,
                    "provider_call_attempted": True,
                    "base_explanation_length": len(base_explanation),
                    "structured_input_keys": sorted(prompt.structured_input.keys()),
                },
            )
            result = await provider.generate_explanation(prompt)
        except Exception as exc:
            try:
                if graph_id:
                    await self._analysis_jobs.save_llm_explanation_failure(
                        graph_id=graph_id,
                        recommendation_id=recommendation.recommendation_id,
                        error_message=GENERIC_LLM_FAILURE_MESSAGE,
                        provider=resolution.provider_name or "",
                        model=resolution.model or "",
                    )
                else:
                    logger.warning(
                        "remediation_explanation_persistence_skipped",
                        extra={
                            "cluster_id": cluster_id,
                            "recommendation_id": recommendation.recommendation_id,
                            "user_id": user_id,
                            "stage": "save_llm_explanation_failure",
                            "reason": "missing_graph_id",
                        },
                    )
            except Exception:
                logger.exception(
                    "remediation_explanation_persistence_failed",
                    extra={
                        "cluster_id": cluster_id,
                        "recommendation_id": recommendation.recommendation_id,
                        "user_id": user_id,
                        "stage": "save_llm_explanation_failure",
                        "provider": resolution.provider_name,
                        "model": resolution.model,
                    },
                )
            logger.exception(
                "remediation_provider_call_failed",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "provider": resolution.provider_name,
                    "model": resolution.model,
                    "exception_type": type(exc).__name__,
                    "error_message": str(exc),
                    "provider_call_attempted": True,
                    "explanation_status": "llm_failed_fallback",
                    "fallback_reason": "provider_call_failed",
                },
            )
            return RecommendationExplanationResponse(
                cluster_id=cluster_id,
                recommendation_id=recommendation.recommendation_id,
                explanation_status="llm_failed_fallback",
                used_llm=False,
                base_explanation=base_explanation,
                final_explanation=base_explanation,
                provider=resolution.provider_name,
                model=resolution.model,
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
                "provider_call_attempted": True,
                "explanation_status": "llm_generated",
                    "response_length": len(result.text),
                },
            )
        try:
            if graph_id:
                await self._analysis_jobs.save_llm_explanation_success(
                    graph_id=graph_id,
                    recommendation_id=recommendation.recommendation_id,
                    explanation=result.text,
                    provider=result.provider,
                    model=result.model,
                )
            else:
                logger.warning(
                    "remediation_explanation_persistence_skipped",
                    extra={
                        "cluster_id": cluster_id,
                        "recommendation_id": recommendation.recommendation_id,
                        "user_id": user_id,
                        "stage": "save_llm_explanation_success",
                        "reason": "missing_graph_id",
                    },
                )
        except Exception:
            logger.exception(
                "remediation_explanation_persistence_failed",
                extra={
                    "cluster_id": cluster_id,
                    "recommendation_id": recommendation.recommendation_id,
                    "user_id": user_id,
                    "stage": "save_llm_explanation_success",
                    "provider": result.provider,
                    "model": result.model,
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
    ) -> ProviderResolutionResult:
        config = (
            await self._provider_configs.get_by_provider(user_id, requested_provider)
            if requested_provider
            else await self._provider_configs.get_active(user_id)
        )
        config_is_active = bool(getattr(config, "is_active", False)) if config is not None else None
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
                "config_is_active": config_is_active,
                "lookup_mode": "by_provider" if requested_provider else "active",
            },
        )
        if config is None:
            explanation_status = "provider_config_not_found" if requested_provider else "no_active_provider_config"
            fallback_reason = explanation_status
            logger.info(
                "remediation_provider_resolution",
                extra={
                    "user_id": user_id,
                    "requested_provider": requested_provider,
                    "requested_model": requested_model,
                    "lookup_mode": "by_provider" if requested_provider else "active",
                    "config_found": False,
                    "config_is_active": None,
                    "resolved_provider": None,
                    "resolved_model": None,
                    "explanation_status": explanation_status,
                    "fallback_reason": fallback_reason,
                    "provider_call_attempted": False,
                },
            )
            return ProviderResolutionResult(
                provider_name=None,
                model=None,
                api_key=None,
                explanation_status=explanation_status,
                fallback_reason=fallback_reason,
                config_found=False,
                config_is_active=None,
                lookup_mode="by_provider" if requested_provider else "active",
            )

        provider_name = str(config.provider)
        if not getattr(config, "api_key", None):
            model = requested_model or getattr(config, "default_model", None)
            return ProviderResolutionResult(
                provider_name=provider_name,
                model=model,
                api_key=None,
                explanation_status="api_key_missing",
                fallback_reason="api_key_missing",
                config_found=True,
                config_is_active=config_is_active,
                lookup_mode="by_provider" if requested_provider else "active",
            )

        model = requested_model or getattr(config, "default_model", None) or PROVIDER_DEFAULT_MODELS.get(provider_name)
        if not model:
            return ProviderResolutionResult(
                provider_name=provider_name,
                model=None,
                api_key=str(config.api_key),
                explanation_status="model_unresolved",
                fallback_reason="model_unresolved",
                config_found=True,
                config_is_active=config_is_active,
                lookup_mode="by_provider" if requested_provider else "active",
            )

        return ProviderResolutionResult(
            provider_name=provider_name,
            model=model,
            api_key=str(config.api_key),
            explanation_status="resolved",
            fallback_reason=None,
            config_found=True,
            config_is_active=config_is_active,
            lookup_mode="by_provider" if requested_provider else "active",
        )

    @staticmethod
    def _log_skip(
        event_name: str,
        *,
        cluster_id: str,
        recommendation_id: str,
        user_id: str,
        skip_stage: str,
        explanation_status: str,
        fallback_reason: str | None,
        resolved_provider: str | None = None,
        resolved_model: str | None = None,
        config_found: bool | None = None,
        config_is_active: bool | None = None,
        provider_call_attempted: bool,
    ) -> None:
        logger.info(
            event_name,
            extra={
                "cluster_id": cluster_id,
                "recommendation_id": recommendation_id,
                "user_id": user_id,
                "skip_stage": skip_stage,
                "explanation_status": explanation_status,
                "fallback_reason": fallback_reason,
                "resolved_provider": resolved_provider,
                "resolved_model": resolved_model,
                "config_found": config_found,
                "config_is_active": config_is_active,
                "provider_call_attempted": provider_call_attempted,
            },
        )

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
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        action = RecommendationExplanationService._derive_recommendation_action(recommendation, metadata)
        impact_reason = metadata.get("impact_reason")
        if not isinstance(impact_reason, str) or not impact_reason.strip():
            impact_reason = "이 관계가 risky path를 계속 열어 두기 때문입니다"

        effect_parts: list[str] = []
        path_count = len(recommendation.blocked_path_ids or []) or len(recommendation.blocked_path_indices or [])
        if path_count:
            effect_parts.append(f"risky path {path_count}개를 차단합니다")
        if recommendation.covered_risk is not None:
            effect_parts.append(f"Raw risk를 {recommendation.covered_risk:.2f}만큼 줄입니다")
        if recommendation.cumulative_risk_reduction is not None:
            effect_parts.append(f"cumulative reduction ratio는 {recommendation.cumulative_risk_reduction:.2f}입니다")

        effect_text = ", ".join(effect_parts) if effect_parts else "이 edge를 따라 이어지는 risky path를 줄입니다"
        lines = [
            f"권장 변경: {action}.",
            f"중요한 이유: {impact_reason.rstrip('.')}.",
            f"예상 효과: {effect_text}.",
        ]
        return "\n".join(lines)

    @classmethod
    def _derive_recommendation_context(cls, recommendation: RemediationRecommendationDetailResponse) -> dict[str, Any]:
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        edge_type = str(recommendation.edge_type or "")
        fix_type = str(recommendation.fix_type or "")
        source_type = cls._node_type_from_ref(recommendation.edge_source)
        target_type = cls._node_type_from_ref(recommendation.edge_target)

        edge_meaning_map = {
            "service_account_bound_role": "service account가 role binding을 통해 namespace 범위 권한을 받는 edge입니다.",
            "service_account_bound_cluster_role": "service account가 cluster role binding을 통해 cluster 범위 권한을 받는 edge입니다.",
            "pod_uses_service_account": "이 workload가 referenced service account를 통해 권한을 상속받는 edge입니다.",
            "ingress_exposes_service": "Ingress가 내부 service를 외부 진입점에 연결하는 edge입니다.",
            "iam_role_access_resource": "IAM role이 target resource에 직접 접근하는 edge입니다.",
            "iam_user_access_resource": "IAM user가 target resource에 직접 접근하는 edge입니다.",
            "secret_contains_credentials": "이 secret이 이후 path에서 재사용될 수 있는 credential을 담고 있는 edge입니다.",
            "secret_contains_aws_credentials": "이 secret이 이후 path에서 재사용될 수 있는 AWS credential을 담고 있는 edge입니다.",
            "pod_mounts_secret": "workload가 secret mount를 통해 secret 값을 직접 읽는 edge입니다.",
            "escapes_to": "Pod에서 node 권한 영역으로 넘어가는 container escape edge입니다.",
        }
        control_type_map = {
            "restrict_ingress": "exposure control",
            "remove_role_binding": "privilege binding control",
            "apply_network_policy": "network control",
            "restrict_iam_policy": "IAM permission control",
            "change_service_account": "identity binding control",
            "remove_secret_mount": "secret handling control",
            "remove_privileged": "workload hardening control",
            "rotate_credentials": "credential containment control",
        }
        intent_map = {
            "restrict_ingress": "exposure reduction",
            "remove_role_binding": "privilege reduction",
            "apply_network_policy": "access path blocking",
            "restrict_iam_policy": "privilege reduction",
            "change_service_account": "privilege reduction",
            "remove_secret_mount": "credential containment",
            "remove_privileged": "access path blocking",
            "rotate_credentials": "credential containment",
        }
        security_effect_map = {
            "restrict_ingress": "외부 노출 경로를 줄여 attack path의 진입점을 끊는 효과가 있습니다.",
            "remove_role_binding": "role binding을 줄여 service account로 이어지는 privilege inheritance를 끊는 효과가 있습니다.",
            "apply_network_policy": "workload 간 이동 경로를 막아 lateral movement edge를 차단하는 효과가 있습니다.",
            "restrict_iam_policy": "role assumption 또는 direct resource access 범위를 줄여 후속 접근 단계를 약화시키는 효과가 있습니다.",
            "change_service_account": "이 workload가 상속받는 service account 권한 경로를 끊는 효과가 있습니다.",
            "remove_secret_mount": "workload에서 secret 값을 바로 읽는 경로를 없애 credential reuse를 줄이는 효과가 있습니다.",
            "remove_privileged": "node 권한 영역으로 이어지는 escape 경로를 끊는 효과가 있습니다.",
            "rotate_credentials": "이미 노출된 credential이 이후 path에서 다시 쓰이지 못하게 만드는 효과가 있습니다.",
        }
        operational_caution_map = {
            "restrict_ingress": "Ingress 제한이 필요한 정상 트래픽까지 막지 않는지 확인해야 합니다.",
            "remove_role_binding": "binding 축소 후 workload나 controller가 필요한 API 권한을 잃지 않는지 확인해야 합니다.",
            "apply_network_policy": "network policy 적용 후 정상 서비스 통신이 끊기지 않는지 확인해야 합니다.",
            "restrict_iam_policy": "정책 축소 후 필요한 AWS API 호출이나 AssumeRole 동작이 끊기지 않는지 확인해야 합니다.",
            "change_service_account": "교체한 service account가 workload에 필요한 최소 권한은 여전히 갖고 있는지 확인해야 합니다.",
            "remove_secret_mount": "secret mount 제거 후 애플리케이션이 다른 방식으로 필요한 설정을 계속 읽을 수 있는지 확인해야 합니다.",
            "remove_privileged": "Pod 보안 설정 변경 후 workload가 정상 실행되는지 확인해야 합니다.",
            "rotate_credentials": "credential rotation 이후 dependent service의 연결 정보가 모두 갱신됐는지 확인해야 합니다.",
        }
        path_interruption_map = {
            "service_account_bound_role": "service account -> role binding 권한 경로",
            "service_account_bound_cluster_role": "service account -> cluster role binding 권한 경로",
            "pod_uses_service_account": "workload -> service account 권한 상속 경로",
            "ingress_exposes_service": "external ingress -> internal service 노출 경로",
            "iam_role_access_resource": "IAM role -> resource 직접 접근 경로",
            "iam_user_access_resource": "IAM user -> resource 직접 접근 경로",
            "secret_contains_credentials": "secret -> credential reuse 경로",
            "secret_contains_aws_credentials": "secret -> AWS credential reuse 경로",
            "pod_mounts_secret": "workload -> secret read 경로",
            "escapes_to": "pod -> node escape 경로",
        }

        combination_context_map: dict[tuple[str, str], dict[str, str]] = {
            (
                "change_service_account",
                "pod_uses_service_account",
            ): {
                "edge_meaning": "이 workload가 현재 referenced service account를 통해 path 상의 권한을 상속받고 있는 cut point입니다.",
                "security_effect": "service account를 바꾸면 이 workload에 연결된 inherited permission path를 직접 끊을 수 있습니다.",
                "operational_caution": "교체할 service account가 workload에 필요한 Kubernetes/API access는 유지하는지 확인해야 합니다.",
                "path_interruption": "workload -> service account 권한 상속 경로",
            },
            (
                "remove_role_binding",
                "service_account_bound_role",
            ): {
                "edge_meaning": "이 service account가 namespace 범위 role binding을 통해 추가 권한을 받는 cut point입니다.",
                "security_effect": "role binding을 제거하거나 범위를 줄이면 service account로 이어지는 privilege inheritance를 직접 약화시킬 수 있습니다.",
                "operational_caution": "binding 범위를 줄인 뒤 controller나 workload가 필요한 namespace 권한을 잃지 않는지 확인해야 합니다.",
            },
            (
                "remove_role_binding",
                "service_account_bound_cluster_role",
            ): {
                "edge_meaning": "이 service account가 cluster role binding을 통해 cluster-wide 권한을 받는 cut point입니다.",
                "security_effect": "cluster role binding을 줄이면 service account에 연결된 광범위한 권한 경로를 직접 차단할 수 있습니다.",
                "operational_caution": "cluster 범위 권한을 줄인 뒤 운영에 필요한 cluster-level access가 끊기지 않는지 확인해야 합니다.",
            },
            (
                "rotate_credentials",
                "secret_contains_credentials",
            ): {
                "edge_meaning": "이 secret이 이후 path에서 바로 재사용될 수 있는 credential을 담고 있는 cut point입니다.",
                "security_effect": "credential을 교체하면 이미 노출된 값이 이후 단계에서 다시 사용되는 경로를 끊을 수 있습니다.",
                "operational_caution": "rotation 이후 이 credential을 사용하는 애플리케이션, job, 연결 설정이 모두 새 값으로 갱신됐는지 확인해야 합니다.",
            },
            (
                "restrict_ingress",
                "ingress_exposes_service",
            ): {
                "edge_meaning": "이 Ingress가 내부 service를 외부 path의 진입점으로 열어 두는 cut point입니다.",
                "security_effect": "Ingress 노출을 줄이면 외부에서 시작되는 접근 path 자체를 초기에 차단할 수 있습니다.",
                "operational_caution": "노출 범위를 줄인 뒤에도 필요한 public endpoint나 health check가 유지되는지 확인해야 합니다.",
            },
        }

        blocked_path_count = len(recommendation.blocked_path_ids or []) or len(recommendation.blocked_path_indices or [])
        combined = combination_context_map.get((fix_type, edge_type), {})
        return {
            "source_type": source_type,
            "target_type": target_type,
            "edge_meaning": combined.get("edge_meaning") or edge_meaning_map.get(edge_type),
            "control_type": control_type_map.get(fix_type),
            "recommendation_intent": intent_map.get(fix_type),
            "security_effect": combined.get("security_effect") or security_effect_map.get(fix_type),
            "operational_caution": combined.get("operational_caution") or operational_caution_map.get(fix_type),
            "path_interruption": combined.get("path_interruption") or path_interruption_map.get(edge_type),
            "impact_reason": metadata.get("impact_reason"),
            "blocked_path_count": blocked_path_count,
        }

    @staticmethod
    def _derive_recommendation_action(
        recommendation: RemediationRecommendationDetailResponse,
        metadata: dict[str, Any],
    ) -> str:
        base_action = metadata.get("base_action")
        if isinstance(base_action, str) and base_action.strip():
            return base_action.strip().rstrip(".")

        if recommendation.fix_type:
            display = FIX_TYPE_DISPLAY_MAP_KO.get(recommendation.fix_type)
            if isinstance(display, str) and display.strip():
                return display.strip().rstrip(".")

        return "권장 변경을 적용"

    @staticmethod
    def _node_type_from_ref(node_ref: str | None) -> str | None:
        if not isinstance(node_ref, str) or ":" not in node_ref:
            return None
        prefix = node_ref.split(":", 1)[0].strip()
        return prefix or None

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
            "derived_context": RecommendationExplanationService._derive_recommendation_context(recommendation),
        }
