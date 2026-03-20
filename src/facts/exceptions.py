"""
Custom exceptions for the Fact pipeline.
"""


class FactPipelineError(Exception):
    """Base exception for all Fact pipeline errors"""
    pass


class ValidationError(FactPipelineError):
    """Raised when Fact validation fails"""
    pass


class ExtractionError(FactPipelineError):
    """Raised when Fact extraction fails"""
    pass


class NodeIDError(FactPipelineError):
    """Raised when Node ID format is invalid"""
    pass


class GraphBuildError(FactPipelineError):
    """Raised when graph construction fails"""
    pass