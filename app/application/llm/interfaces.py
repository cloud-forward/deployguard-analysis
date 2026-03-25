from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class RecommendationExplanationPrompt:
    target_type: str
    recommendation_id: str
    base_explanation: str
    structured_input: dict[str, Any]
    provider: str
    model: str
    api_key: str


@dataclass(frozen=True)
class LLMExplanationResult:
    text: str
    provider: str
    model: str


@runtime_checkable
class ExplanationProvider(Protocol):
    provider_name: str

    async def generate_explanation(
        self,
        prompt: RecommendationExplanationPrompt,
    ) -> LLMExplanationResult:
        ...
