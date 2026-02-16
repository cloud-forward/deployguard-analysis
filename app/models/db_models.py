"""
Deprecated: ORM models moved to gateway layer to enforce Clean Architecture boundaries.

Use models from: app.gateway.db.models
This module remains only as a compatibility shim and will be removed.
"""

# Re-export for backward compatibility if anything still imports this module.
from app.gateway.models import *  # noqa: F401,F403
