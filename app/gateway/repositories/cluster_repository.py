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
    ) -> Cluster:
        cluster = Cluster(
            name=name,
            cluster_type=cluster_type,
            user_id=user_id,
            description=description,
            api_token=api_token,
            aws_account_id=aws_account_id,
            aws_role_arn=aws_role_arn,
            aws_region=aws_region,
        )
        self._session.add(cluster)
        await self._session.commit()
        await self._session.refresh(cluster)
        return cluster

    async def get_by_id(self, cluster_id: str, user_id: Optional[str] = None) -> Optional[Cluster]:
        query = select(Cluster).where(Cluster.id == cluster_id)
        if user_id is not None:
            query = query.where(Cluster.user_id == user_id)
        result = await self._session.execute(query)
        return result.scalars().first()

    async def get_by_name(self, name: str) -> Optional[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.name == name)
        )
        return result.scalars().first()

    async def get_by_api_token(self, api_token: str) -> Optional[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.api_token == api_token)
        )
        return result.scalars().first()

    async def list_all(self, user_id: str) -> List[Cluster]:
        result = await self._session.execute(
            select(Cluster).where(Cluster.user_id == user_id)
        )
        return list(result.scalars().all())

    async def update(self, cluster_id: str, user_id: Optional[str] = None, **kwargs) -> Optional[Cluster]:
        query = select(Cluster).where(Cluster.id == cluster_id)
        if user_id is not None:
            query = query.where(Cluster.user_id == user_id)
        result = await self._session.execute(query)
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
