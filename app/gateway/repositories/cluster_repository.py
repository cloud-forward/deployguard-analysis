"""
SQLAlchemy implementation of ClusterRepository.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional, List
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.repositories.cluster_repository import ClusterRepository
from app.gateway.models import Cluster


class SQLAlchemyClusterRepository(ClusterRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, name: str, cluster_type: str, description: Optional[str] = None) -> Cluster:
        cluster = Cluster(
            name=name,
            cluster_type=cluster_type,
            description=description,
        )
        self._session.add(cluster)
        await self._session.commit()
        await self._session.refresh(cluster)
        return cluster

    async def get_by_id(self, cluster_id: str) -> Optional[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.id == cluster_id)
        )
        return result.scalars().first()

    async def get_by_name(self, name: str) -> Optional[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.name == name)
        )
        return result.scalars().first()

    async def list_all(self) -> List[Cluster]:
        result = await self._session.execute(select(Cluster))
        return list(result.scalars().all())

    async def update(self, cluster_id: str, **kwargs) -> Optional[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.id == cluster_id)
        )
        cluster = result.scalars().first()
        if not cluster:
            return None
        
        for key, value in kwargs.items():
            if hasattr(cluster, key):
                setattr(cluster, key, value)
        
        cluster.updated_at = datetime.utcnow()
        await self._session.commit()
        await self._session.refresh(cluster)
        return cluster

    async def delete(self, cluster_id: str) -> bool:
        result = await self._session.execute(
            delete(Cluster).where(Cluster.id == cluster_id)
        )
        await self._session.commit()
        return result.rowcount > 0
