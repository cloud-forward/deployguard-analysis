"""
SQLAlchemy implementation of ScanRepository.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.constants import ACTIVE_SCAN_STATUSES
from app.domain.repositories.scan_repository import ScanRepository
from app.models.db_models import ScanRecord


class SQLAlchemyScanRepository(ScanRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, scan_id: str, cluster_id: str, scanner_type: str) -> ScanRecord:
        record = ScanRecord(
            scan_id=scan_id,
            cluster_id=cluster_id,
            scanner_type=scanner_type,
            status="created",
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        return record

    async def get_by_scan_id(self, scan_id: str) -> Optional[ScanRecord]:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        return result.scalars().first()

    async def update_status(self, scan_id: str, status: str, **kwargs) -> ScanRecord:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        record = result.scalars().first()
        record.status = status
        record.updated_at = datetime.utcnow()
        if "completed_at" in kwargs:
            record.completed_at = kwargs["completed_at"]
        await self._session.commit()
        await self._session.refresh(record)
        return record

    async def update_files(self, scan_id: str, s3_keys: list[str]) -> ScanRecord:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        record = result.scalars().first()
        record.s3_keys = s3_keys
        record.updated_at = datetime.utcnow()
        await self._session.commit()
        await self._session.refresh(record)
        return record

    async def list_by_cluster(self, cluster_id: str) -> list[ScanRecord]:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.cluster_id == cluster_id)
        )
        return list(result.scalars().all())

    async def find_active_scan(self, cluster_id: str, scanner_type: str) -> Optional[ScanRecord]:
        active_statuses = ACTIVE_SCAN_STATUSES
        result = await self._session.execute(
            select(ScanRecord).where(
                ScanRecord.cluster_id == cluster_id,
                ScanRecord.scanner_type == scanner_type,
                ScanRecord.status.in_(active_statuses),
            )
        )
        return result.scalars().first()
