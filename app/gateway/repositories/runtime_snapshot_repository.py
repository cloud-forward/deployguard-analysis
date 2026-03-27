"""
SQLAlchemy implementation of RuntimeSnapshotRepository.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.runtime_snapshot_repository import RuntimeSnapshotRepository
from app.gateway.models import RuntimeSnapshot


class SQLAlchemyRuntimeSnapshotRepository(RuntimeSnapshotRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(
        self,
        cluster_id: str,
        s3_key: str,
        snapshot_at: datetime,
        uploaded_at: datetime,
        fact_count: int | None = None,
    ) -> RuntimeSnapshot:
        record = RuntimeSnapshot(
            cluster_id=cluster_id,
            s3_key=s3_key,
            snapshot_at=snapshot_at,
            uploaded_at=uploaded_at,
            fact_count=fact_count,
        )
        self._session.add(record)
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError:
            await self._session.rollback()
            existing = await self.get_by_s3_key(s3_key)
            if existing is None:
                raise
            return existing

    async def get_by_s3_key(self, s3_key: str) -> RuntimeSnapshot | None:
        result = await self._session.execute(
            select(RuntimeSnapshot).where(RuntimeSnapshot.s3_key == s3_key)
        )
        return result.scalars().first()

    async def get_latest_by_cluster_id(self, cluster_id: str) -> RuntimeSnapshot | None:
        result = await self._session.execute(
            select(RuntimeSnapshot)
            .where(RuntimeSnapshot.cluster_id == cluster_id)
            .order_by(RuntimeSnapshot.uploaded_at.desc())
            .limit(1)
        )
        return result.scalars().first()
