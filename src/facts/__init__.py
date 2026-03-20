"""
Facts package - Canonical Fact extraction and validation.
"""
from src.facts.canonical_fact import Fact, FactCollection
from src.facts.types import FactType, NodeType
from src.facts.id_generator import NodeIDGenerator
from src.facts.exceptions import (
    FactPipelineError,
    ValidationError,
    ExtractionError,
    NodeIDError,
    GraphBuildError,
)

__all__ = [
    "Fact",
    "FactCollection",
    "FactType",
    "NodeType",
    "NodeIDGenerator",
    "FactPipelineError",
    "ValidationError",
    "ExtractionError",
    "NodeIDError",
    "GraphBuildError",
]