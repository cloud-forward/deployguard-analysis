from typing import List

from src.facts.canonical_fact import Fact, FactCollection
from src.facts.validation.validators import FactValidator
from src.facts.logger import setup_logger


class ValidationGate:
    """
    Main validation gate for fact collections.
    """

    def __init__(self, level: str = "normal"):
        self.level = level
        self.validator = FactValidator()
        self.logger = setup_logger("validation_gate")

    def validate(
        self, facts: List[Fact], scan_id: str = "unknown"
    ) -> tuple[List[Fact], FactCollection]:
        """
        Backward-compatible API.
        Returns (valid_facts, collection).
        """
        collection = self.validate_debug(facts, scan_id=scan_id)
        return collection.facts, collection

    def validate_debug(
        self, facts: List[Fact], scan_id: str = "unknown"
    ) -> FactCollection:
        """
        Debug-friendly validation API.
        Produces a FactCollection with counts + detailed errors.
        """
        self.logger.info(
            f"Validation started: {len(facts)} facts",
            stage="validation",
            scan_id=scan_id,
            level=self.level,
        )

        collection = FactCollection(scan_id=scan_id)

        for fact in facts:
            errors = self.validator.validate(fact)

            if not errors:
                collection.add(fact)
                continue

            collection.error_count += 1
            collection.skipped_count += 1
            collection.errors.append(
                {
                    "fact_type": fact.fact_type,
                    "subject_id": fact.subject_id,
                    "subject_type": fact.subject_type,
                    "object_id": fact.object_id,
                    "object_type": fact.object_type,
                    "errors": errors,
                }
            )

            self.logger.warning(
                f"Fact validation failed: {fact.fact_type}",
                stage="validation",
                scan_id=scan_id,
                subject_id=fact.subject_id,
                object_id=fact.object_id,
                errors=errors,
            )

        self.logger.info(
            f"Validation complete: {len(collection.facts)} valid, "
            f"{collection.error_count} errors, {collection.skipped_count} skipped",
            stage="validation",
            scan_id=scan_id,
        )

        return collection