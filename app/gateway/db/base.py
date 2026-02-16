"""
SQLAlchemy Declarative Base lives here. Gateway-only.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass
