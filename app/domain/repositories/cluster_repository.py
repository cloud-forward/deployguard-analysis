"""
Domain repository interface for Cluster entities.
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable, Optional, List


@runtime_checkable
class ClusterRepository(Protocol):
    async def create(
        self,
        name: str,
        cluster_type: str,
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        api_token: Optional[str] = None,
        aws_account_id: Optional[str] = None,
        aws_role_arn: Optional[str] = None,
        aws_region: Optional[str] = None,
    ) -> object:
        """Create a new cluster."""
        ...

    async def get_by_id(self, cluster_id: str) -> Optional[object]:
        """Get a cluster by its ID."""
        ...

    async def get_by_name(self, name: str) -> Optional[object]:
        """Get a cluster by its name."""
        ...

    async def get_by_api_token(self, api_token: str) -> Optional[object]:
        """Get a cluster by its scanner API token."""
        ...

    async def list_all(self, user_id: str) -> List[object]:
        """List all clusters for a user."""
        ...

    async def update(self, cluster_id: str, **kwargs) -> Optional[object]:
        """Update a cluster's details."""
        ...

    async def delete(self, cluster_id: str) -> bool:
        """Delete a cluster."""
        ...
