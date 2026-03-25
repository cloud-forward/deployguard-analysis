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
        payload = {
            "model": prompt.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You rewrite remediation recommendation explanations for a security product. "
                        "Stay grounded in the provided structured input. "
                        "Do not invent runtime evidence, attack steps, or impact not present in the input. "
                        "Respond with plain text only."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Base explanation:\n{prompt.base_explanation}\n\n"
                        f"Structured input:\n{json.dumps(prompt.structured_input, sort_keys=True)}"
                    ),
                },
            ],
            "temperature": 0.2,
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
