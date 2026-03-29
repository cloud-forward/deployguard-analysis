from __future__ import annotations

import json

import httpx

from app.application.llm.interfaces import (
    ExplanationProvider,
    LLMExplanationResult,
    RecommendationExplanationPrompt,
)


class OpenAIExplanationClient(ExplanationProvider):
    provider_name = "openai"
    _base_url = "https://api.openai.com/v1/chat/completions"

    async def generate_explanation(
        self,
        prompt: RecommendationExplanationPrompt,
    ) -> LLMExplanationResult:
        data = prompt.structured_input
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        derived = data.get("derived_context") if isinstance(data.get("derived_context"), dict) else {}
        blocked_path_count = len(data.get("blocked_path_ids") or []) or len(data.get("blocked_path_indices") or [])
        key_context = [
            f"- recommendation_id: {prompt.recommendation_id}",
            f"- recommendation_rank: {data.get('recommendation_rank')}",
            f"- edge_type: {data.get('edge_type')}",
            f"- fix_type: {data.get('fix_type')}",
            f"- fix_description: {data.get('fix_description')}",
            f"- edge_source: {data.get('edge_source')}",
            f"- edge_target: {data.get('edge_target')}",
            f"- blocked_path_count: {blocked_path_count}",
            f"- covered_risk: {data.get('covered_risk')}",
            f"- cumulative_risk_reduction: {data.get('cumulative_risk_reduction')}",
            f"- impact_reason: {metadata.get('impact_reason')}",
        ]
        derived_context = [
            f"- recommendation_intent: {derived.get('recommendation_intent')}",
            f"- control_type: {derived.get('control_type')}",
            f"- source_type: {derived.get('source_type')}",
            f"- target_type: {derived.get('target_type')}",
            f"- edge_meaning: {derived.get('edge_meaning')}",
            f"- path_interruption: {derived.get('path_interruption')}",
            f"- security_effect: {derived.get('security_effect')}",
            f"- operational_caution: {derived.get('operational_caution')}",
        ]
        payload = {
            "model": prompt.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You produce a richer remediation recommendation explanation for a security product. "
                        "Stay grounded in the provided structured input. "
                        "Do not invent runtime evidence, attack steps, or impact not present in the input. "
                        "Use the base explanation only as a starting point, not as text to paraphrase. "
                        "Do not closely paraphrase the base explanation and do not repeat the same point in different words. "
                        "Prefer recommendation-specific interpretation over generic security language. "
                        "Prefer explaining exactly which permission, exposure, or credential path is being interrupted. "
                        "Name the control boundary being changed when the context supports it. "
                        "Explain why this exact edge is the right cut point for the recommendation. "
                        "Tie every claim to the path, permission, exposure, binding, or credential flow described in the input. "
                        "Cover, concisely: why this matters in this specific edge/path context, what changes operationally or security-wise if applied, one realistic caution or tradeoff, and what to verify after applying it. "
                        "Avoid empty claims like improving security posture unless tied to the concrete recommendation context. "
                        "Avoid generic endings such as saying risk is reduced without naming what path or access is actually interrupted. "
                        "Avoid generic closing filler and do not restate the same metric twice. "
                        "Return the explanation in natural Korean by default, but keep technical security terms in English when that reads more naturally. "
                        "Keep it concise, product-facing, and technically useful. "
                        "Respond with plain text only."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "다음 remediation recommendation에 대해 더 유용한 explanation을 작성하세요.\n"
                        "base_explanation은 출발점일 뿐이며, 그대로 재진술하거나 문장을 약간만 바꿔 반복하지 마세요.\n"
                        "짧지만 구체적으로, 이 edge가 왜 중요한 cut point인지와 적용 후 무엇을 확인해야 하는지 설명하세요.\n"
                        "generic한 마무리 문장이나 추상적인 보안 문구로 끝내지 말고, 실제로 끊기는 permission/exposure/credential path를 설명하세요.\n\n"
                        f"Starting point:\n{prompt.base_explanation}\n\n"
                        "Key context:\n"
                        + "\n".join(key_context)
                        + "\n\nInterpreted context:\n"
                        + "\n".join(derived_context)
                        + "\n\nStructured JSON (facts only):\n"
                        + json.dumps(prompt.structured_input, sort_keys=True)
                    ),
                },
            ],
            "temperature": 0.35,
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                self._base_url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {prompt.api_key}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        body = response.json()
        text = (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Provider returned an empty explanation")
        return LLMExplanationResult(
            text=text.strip(),
            provider=self.provider_name,
            model=prompt.model,
        )
