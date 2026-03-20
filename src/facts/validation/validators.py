"""
Individual validator functions for facts.
"""
from typing import Any, Dict, List

from src.facts.canonical_fact import Fact
from src.facts.types import FactType
from src.facts.validation.rules import ValidationRules


class FactValidator:
    """Validates individual facts"""
    
    def __init__(self):
        self.rules = ValidationRules()
    
    def validate(self, fact: Fact) -> List[str]:
        """
        Validate a single fact.
        
        Returns:
            List of error messages (empty if valid)
        """
        errors = []
        
        # 1. Required fields
        errors.extend(self._validate_required_fields(fact))
        
        # 2. Fact type
        errors.extend(self._validate_fact_type(fact))
        
        # 3. Node ID prefix
        errors.extend(self._validate_node_id_prefix(fact))
        
        # 4. Type combination
        errors.extend(self._validate_type_combination(fact))
        
        # 5. Self-referential
        errors.extend(self._validate_not_self_referential(fact))
        
        # 6. Metadata
        errors.extend(self._validate_metadata(fact))
        
        return errors
    
    def _validate_required_fields(self, fact: Fact) -> List[str]:
        """Validate required fields are present"""
        errors = []
        
        required = ["fact_type", "subject_id", "subject_type", "object_id", "object_type"]
        
        for field in required:
            if not getattr(fact, field, None):
                errors.append(f"Required field '{field}' is empty")
        
        if fact.metadata is None:
            errors.append("metadata cannot be None")
        
        return errors
    
    def _validate_fact_type(self, fact: Fact) -> List[str]:
        """Validate fact_type is allowed"""
        errors = []
        
        try:
            # Check if it's a valid FactType enum value
            if fact.fact_type not in [ft.value for ft in FactType]:
                errors.append(f"Unknown fact_type: {fact.fact_type}")
        except Exception:
            errors.append(f"Invalid fact_type: {fact.fact_type}")
        
        return errors
    
    def _validate_node_id_prefix(self, fact: Fact) -> List[str]:
        """Validate node IDs have correct prefix"""
        errors = []
        
        # Subject
        expected_prefix = self.rules.TYPE_PREFIX_MAP.get(fact.subject_type)
        if expected_prefix and not fact.subject_id.startswith(expected_prefix):
            errors.append(
                f"subject_id prefix mismatch: expected '{expected_prefix}', "
                f"got '{fact.subject_id}'"
            )
        
        # Object
        expected_prefix = self.rules.TYPE_PREFIX_MAP.get(fact.object_type)
        if expected_prefix and not fact.object_id.startswith(expected_prefix):
            errors.append(
                f"object_id prefix mismatch: expected '{expected_prefix}', "
                f"got '{fact.object_id}'"
            )
        
        return errors
    
    def _validate_type_combination(self, fact: Fact) -> List[str]:
        """Validate subject_type and object_type combination is allowed"""
        errors = []
        
        allowed = self.rules.ALLOWED_COMBINATIONS.get(fact.fact_type, set())
        combination = (fact.subject_type, fact.object_type)
        
        if combination not in allowed:
            errors.append(
                f"Invalid type combination for {fact.fact_type}: "
                f"({fact.subject_type}, {fact.object_type})"
            )
        
        return errors
    
    def _validate_not_self_referential(self, fact: Fact) -> List[str]:
        """Validate fact is not self-referential"""
        errors = []
        
        if fact.subject_id == fact.object_id:
            errors.append("Self-referential fact not allowed")
        
        return errors
    
    def _validate_metadata(self, fact: Fact) -> List[str]:
        """Validate metadata based on fact_type"""
        errors = []
        
        if not isinstance(fact.metadata, dict):
            errors.append("metadata must be a dict")
            return errors
        
        # Fact-type specific validation
        if fact.fact_type == FactType.LATERAL_MOVE.value:
            errors.extend(self._validate_lateral_move_metadata(fact.metadata))
        elif fact.fact_type in [
            FactType.SECRET_CONTAINS_CREDENTIALS.value,
            FactType.SECRET_CONTAINS_AWS_CREDENTIALS.value,
        ]:
            errors.extend(self._validate_credentials_metadata(fact.metadata))
        
        return errors
    
    def _validate_lateral_move_metadata(self, metadata: Dict[str, Any]) -> List[str]:
        """Validate lateral_move metadata"""
        errors = []
        
        required = ["reason", "cross_namespace", "target_port", "compliance_violation"]
        
        for field in required:
            if field not in metadata:
                errors.append(f"lateral_move missing required metadata: {field}")
        
        # Validate types
        if "target_port" in metadata and not isinstance(metadata["target_port"], int):
            errors.append("target_port must be int")
        
        if "compliance_violation" in metadata and metadata["compliance_violation"] != "PRCC-024":
            errors.append("compliance_violation must be 'PRCC-024'")
        
        return errors
    
    def _validate_credentials_metadata(self, metadata: Dict[str, Any]) -> List[str]:
        """Validate credentials metadata"""
        errors = []
        
        if "confidence" in metadata:
            if metadata["confidence"] not in self.rules.ALLOWED_CONFIDENCE:
                errors.append(f"Invalid confidence: {metadata['confidence']}")
        
        return errors