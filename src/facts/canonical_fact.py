"""
Canonical Fact data model.
Represents a single relationship between two infrastructure resources.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from src.facts.types import FactType, NodeType


@dataclass
class Fact:
    """
    Canonical Fact representing a relationship between two resources.
    
    Attributes:
        fact_type: Type of relationship (must be one of FactType enum)
        subject_id: Source node ID (e.g., "pod:production:web-app")
        subject_type: Source node type (e.g., "pod")
        object_id: Target node ID (e.g., "sa:production:web-sa")
        object_type: Target node type (e.g., "service_account")
        metadata: Additional context (fact_type specific)
    """
    
    fact_type: str
    subject_id: str
    subject_type: str
    object_id: str
    object_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Internal tracking
    created_at: Optional[str] = None
    
    def __post_init__(self):
        """Auto-generate timestamp if not provided"""
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Ensure metadata is dict
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "fact_type": self.fact_type,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }
    
    def __repr__(self) -> str:
        return (
            f"Fact(type={self.fact_type}, "
            f"{self.subject_id} → {self.object_id})"
        )


@dataclass
class FactCollection:
    """Collection of Facts with metadata"""
    
    scan_id: str
    facts: list[Fact] = field(default_factory=list)
    skipped_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    errors: list[Dict[str, Any]] = field(default_factory=list)
    
    def add(self, fact: Fact):
        """Add a fact to the collection"""
        self.facts.append(fact)
    
    def extend(self, facts: list[Fact]):
        """Add multiple facts"""
        self.facts.extend(facts)
    
    def __len__(self) -> int:
        return len(self.facts)
    
    def __iter__(self):
        return iter(self.facts)