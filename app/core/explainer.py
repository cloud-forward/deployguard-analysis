"""
Explanation layer module.
Responsible for generating human-readable explanations of risks and paths.
LLM-ready but currently optional.
"""
from typing import Any, Dict

class Explainer:
    """
    Generates explanations for analysis results.
    Can be integrated with LLMs to provide context-aware security insights.
    """
    
    def explain_path(self, path_data: Any) -> str:
        """
        Creates a natural language description of a discovered attack path.
        
        TODO: Implement explanation generation or LLM prompt logic.
        """
        pass

    def explain_risk_score(self, score: float, factors: Dict[str, Any]) -> str:
        """
        Explains why a specific risk score was assigned.
        """
        pass
