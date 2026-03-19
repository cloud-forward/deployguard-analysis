"""
SQLAlchemy implementation of InventorySnapshotRepository.
"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.repositories.inventory_snapshot_repository import InventorySnapshotRepository
from app.gateway.models import InventorySnapshot


class SQLAlchemyInventorySnapshotRepository(InventorySnapshotRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, cluster_id: str, scan_id: str, scanned_at, raw_result_json: dict) -> InventorySnapshot:
        snapshot = InventorySnapshot(
            cluster_id=cluster_id,
            scan_id=scan_id,
            scanned_at=scanned_at,
            raw_result_json=raw_result_json,
        )
        self._session.add(snapshot)
        await self._session.commit()
        await self._session.refresh(snapshot)
        return snapshot

    async def get_latest_by_cluster(self, cluster_id: str) -> InventorySnapshot | None:
        result = await self._session.execute(
            select(InventorySnapshot)
            .where(InventorySnapshot.cluster_id == cluster_id)
            .order_by(InventorySnapshot.scanned_at.desc(), InventorySnapshot.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def list_latest(self) -> list[InventorySnapshot]:
        latest_scanned_at = (
            select(
                InventorySnapshot.cluster_id,
                func.max(InventorySnapshot.scanned_at).label("max_scanned_at"),
            )
            .group_by(InventorySnapshot.cluster_id)
            .subquery()
        )

        result = await self._session.execute(
            select(InventorySnapshot)
            .join(
                latest_scanned_at,
                (InventorySnapshot.cluster_id == latest_scanned_at.c.cluster_id)
                & (InventorySnapshot.scanned_at == latest_scanned_at.c.max_scanned_at),
            )
        )
        return list(result.scalars().all())
