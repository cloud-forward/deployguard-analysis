"""
Base extractor class for all fact extractors.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from src.facts.canonical_fact import Fact, FactCollection
from src.facts.logger import setup_logger


class BaseExtractor(ABC):
    """Abstract base class for all fact extractors"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(f"extractor.{name}")
    
    @abstractmethod
    def extract(self, scan_data: Dict[str, Any], **kwargs) -> List[Fact]:
        """
        Extract facts from scan data.
        
        Args:
            scan_data: Scanner output data
            **kwargs: Additional context (e.g., other scan results)
        
        Returns:
            List of extracted Facts
        """
        pass
    
    def _log_extraction_start(self, scan_id: str):
        """Log extraction start"""
        self.logger.info(
            f"{self.name} extraction started",
            stage="fact_extraction",
            extractor=self.name,
            scan_id=scan_id,
        )
    
    def _log_extraction_complete(self, scan_id: str, fact_count: int):
        """Log extraction completion"""
        self.logger.info(
            f"{self.name} extraction completed",
            stage="fact_extraction",
            extractor=self.name,
            scan_id=scan_id,
            fact_count=fact_count,
        )
    
    def _log_error(self, scan_id: str, error: Exception, context: Dict[str, Any]):
        """Log extraction error"""
        self.logger.error(
            f"{self.name} extraction error: {str(error)}",
            stage="fact_extraction",
            extractor=self.name,
            scan_id=scan_id,
            error_type=type(error).__name__,
            **context,
        )