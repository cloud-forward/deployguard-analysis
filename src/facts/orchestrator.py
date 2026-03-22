from typing import Dict, Any, List
import asyncio

from src.facts.canonical_fact import Fact, FactCollection, FactPipelineDebugResult
from src.facts.extractors.k8s_extractor import K8sFactExtractor
from src.facts.extractors.aws_extractor import AWSFactExtractor
from src.facts.extractors.lateral_move_extractor import LateralMoveExtractor
from src.facts.validation.validation_gate import ValidationGate
from src.facts.logger import setup_logger


class FactOrchestrator:
    """
    Orchestrates fact extraction from multiple scanners.
    Provides both:
    - extract_all(): backward-compatible production API
    - extract_all_debug(): debug-friendly API for harness/testing
    """

    def __init__(self):
        self.k8s_extractor = K8sFactExtractor()
        self.aws_extractor = AWSFactExtractor()
        self.lateral_extractor = LateralMoveExtractor()
        self.validator = ValidationGate(level="normal")
        self.logger = setup_logger("fact_orchestrator")

    async def extract_all(
        self,
        k8s_scan: Dict[str, Any],
        aws_scan: Dict[str, Any],
        image_scan: Dict[str, Any] | None = None,
    ) -> FactCollection:
        debug_result = await self.extract_all_debug(
            k8s_scan=k8s_scan,
            aws_scan=aws_scan,
            image_scan=image_scan,
        )
        return debug_result.to_collection()

    async def extract_all_debug(
        self,
        k8s_scan: Dict[str, Any],
        aws_scan: Dict[str, Any],
        image_scan: Dict[str, Any] | None = None,
    ) -> FactPipelineDebugResult:
        scan_id = k8s_scan.get("scan_id", "unknown")

        self.logger.info(
            "Starting fact extraction",
            scan_id=scan_id,
            stage="orchestration",
        )

        try:
            k8s_facts = await asyncio.to_thread(
                self.k8s_extractor.extract, k8s_scan
            )

            lateral_facts = await asyncio.to_thread(
                self.lateral_extractor.extract, k8s_scan
            )

            aws_facts, bridge_output = await asyncio.to_thread(
                self.aws_extractor.extract_with_debug, aws_scan, k8s_scan=k8s_scan
            )

            all_facts: List[Fact] = []
            all_facts.extend(k8s_facts)
            all_facts.extend(lateral_facts)
            all_facts.extend(aws_facts)

            self.logger.info(
                f"Fact extraction complete: {len(all_facts)} total facts",
                scan_id=scan_id,
                k8s_facts=len(k8s_facts),
                lateral_facts=len(lateral_facts),
                aws_facts=len(aws_facts),
            )

            collection = self.validator.validate_debug(all_facts, scan_id)
            summary = collection.summary_payload(raw_fact_count=len(all_facts))

            self.logger.info(
                f"Validation complete: {len(collection.facts)} valid, "
                f"{collection.error_count} errors, {collection.skipped_count} skipped",
                scan_id=scan_id,
            )

            return FactPipelineDebugResult(
                scan_id=scan_id,
                k8s_raw_facts=k8s_facts,
                lateral_raw_facts=lateral_facts,
                aws_raw_facts=aws_facts,
                all_raw_facts=all_facts,
                valid_facts=list(collection.facts),
                validation_errors=list(collection.errors),
                bridge_output=bridge_output,
                summary=summary,
            )

        except Exception as e:
            self.logger.error(
                f"Fact extraction failed: {str(e)}",
                scan_id=scan_id,
                error_type=type(e).__name__,
            )
            raise