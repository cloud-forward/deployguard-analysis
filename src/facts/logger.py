"""
Structured logging utilities for the Fact pipeline.
"""
import logging
import json
from datetime import datetime
from typing import Any, Dict, Optional


class StructuredLogger:
    """Structured logger with JSON formatting"""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Console handler with JSON format
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)
    
    def _build_context(self, **kwargs) -> Dict[str, Any]:
        """Build log context with timestamp"""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **{k: v for k, v in kwargs.items() if v is not None}
        }
    
    def info(self, message: str, **context):
        self.logger.info(message, extra={"context": self._build_context(**context)})
    
    def warning(self, message: str, **context):
        self.logger.warning(message, extra={"context": self._build_context(**context)})
    
    def error(self, message: str, **context):
        self.logger.error(message, extra={"context": self._build_context(**context)})
    
    def fatal(self, message: str, **context):
        self.logger.critical(message, extra={"context": self._build_context(**context)})


class JSONFormatter(logging.Formatter):
    """Format log records as JSON"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        
        # Add context if present
        if hasattr(record, "context"):
            log_data.update(record.context)
        
        return json.dumps(log_data, ensure_ascii=False)


def setup_logger(name: str, level: int = logging.INFO) -> StructuredLogger:
    """Factory function to create structured logger"""
    return StructuredLogger(name, level)