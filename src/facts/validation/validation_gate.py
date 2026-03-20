"""
Validation gate for fact collections.
"""
from typing import Dict, List, Any

from src.facts.canonical_fact import Fact, FactCollection
from src.facts.validation.validators import FactValidator
from src.facts.logger import setup_logger


class ValidationGate:
    """Main validation gate for fact collections"""
    
    def __init__(self, level: str = "normal"):
        """
        Initialize validation gate.
        
        Args:
            level: Validation level ('strict', 'normal', 'permissive')
        """
        self.level = level
        self.validator = FactValidator()
        self.logger = setup_logger("validation_gate")
    
    def validate(
        self, facts: List[Fact], scan_id: str = "unknown"
    ) -> tuple[List[Fact], FactCollection]:
        """
        Validate facts and return valid ones.
        
        Args:
            facts: List of facts to validate
            scan_id: Scan ID for logging
        
        Returns:
            Tuple of (valid_facts, collection_with_errors)
        """
        self.logger.info(
            f"Validation started: {len(facts)} facts",
            stage="validation",
            scan_id=scan_id,
            level=self.level,
        )
        
        collection = FactCollection(scan_id=scan_id)
        valid_facts = []
        
        for fact in facts:
            errors = self.validator.validate(fact)
            
            if not errors:
                # Valid fact
                valid_facts.append(fact)
                collection.add(fact)
            else:
                # Invalid fact
                collection.error_count += 1
                collection.errors.append({
                    "fact_type": fact.fact_type,
                    "subject_id": fact.subject_id,
                    "object_id": fact.object_id,
                    "errors": errors,
                })
                
                self.logger.warning(
                    f"Fact validation failed: {fact.fact_type}",
                    stage="validation",
                    scan_id=scan_id,
                    subject_id=fact.subject_id,
                    object_id=fact.object_id,
                    errors=errors,
                )
        
        self.logger.info(
            f"Validation complete: {len(valid_facts)} valid, {collection.error_count} errors",
            stage="validation",
            scan_id=scan_id,
        )
        
        return valid_facts, collection