"""
Fact extraction orchestrator.
Coordinates all extractors and validation.
"""
from typing import Dict, Any, List
import asyncio

from src.facts.canonical_fact import Fact, FactCollection
from src.facts.extractors.k8s_extractor import K8sFactExtractor
from src.facts.extractors.aws_extractor import AWSFactExtractor
from src.facts.extractors.lateral_move_extractor import LateralMoveExtractor
from src.facts.validation.validation_gate import ValidationGate
from src.facts.logger import setup_logger


class FactOrchestrator:
    """Orchestrates fact extraction from multiple scanners"""
    
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
        """
        Extract and validate facts from all scanners.
        
        Args:
            k8s_scan: K8s scanner output
            aws_scan: AWS scanner output
            image_scan: Image scanner output (optional)
        
        Returns:
            FactCollection with validated facts
        """
        scan_id = k8s_scan.get("scan_id", "unknown")
        
        self.logger.info(
            "Starting fact extraction",
            scan_id=scan_id,
            stage="orchestration",
        )
        
        all_facts: List[Fact] = []
        
        try:
            # Phase 1-3: K8s facts
            k8s_facts = await asyncio.to_thread(
                self.k8s_extractor.extract, k8s_scan
            )
            all_facts.extend(k8s_facts)
            
            # Phase 4: Lateral movement
            lateral_facts = await asyncio.to_thread(
                self.lateral_extractor.extract, k8s_scan
            )
            all_facts.extend(lateral_facts)
            
            # Phase 5: AWS cross-domain facts
            aws_facts = await asyncio.to_thread(
                self.aws_extractor.extract, aws_scan, k8s_scan=k8s_scan
            )
            all_facts.extend(aws_facts)
            
            self.logger.info(
                f"Fact extraction complete: {len(all_facts)} total facts",
                scan_id=scan_id,
                k8s_facts=len(k8s_facts),
                lateral_facts=len(lateral_facts),
                aws_facts=len(aws_facts),
            )
            
            # Validate all facts
            valid_facts, collection = self.validator.validate(all_facts, scan_id)
            collection.facts = valid_facts
            
            self.logger.info(
                f"Validation complete: {len(valid_facts)} valid, "
                f"{collection.error_count} errors",
                scan_id=scan_id,
            )
            
            return collection
            
        except Exception as e:
            self.logger.error(
                f"Fact extraction failed: {str(e)}",
                scan_id=scan_id,
                error_type=type(e).__name__,
            )
            raise