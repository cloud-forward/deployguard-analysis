"""
Graph data models for nodes and edges.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class GraphNode:
    """Represents a node in the attack graph"""
    
    id: str
    type: str
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    base_risk: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "type": self.type,
            "is_entry_point": self.is_entry_point,
            "is_crown_jewel": self.is_crown_jewel,
            "base_risk": self.base_risk,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """Represents an edge in the attack graph"""
    
    source: str
    target: str
    type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "metadata": self.metadata,
        }