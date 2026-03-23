"""
SQLAlchemy implementation of ScanRepository.
"""
from __future__ import annotations
from datetime import datetime
import logging
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.constants import ACTIVE_SCAN_STATUSES, SCAN_STATUS_CREATED, SCAN_STATUS_PROCESSING
from app.domain.repositories.scan_repository import ScanRepository
from app.gateway.models import ScanRecord
from app.models.schemas import RequestSource

logger = logging.getLogger(__name__)


def _context(**kwargs):
    return {key: value for key, value in kwargs.items() if value is not None}


class SQLAlchemyScanRepository(ScanRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def _rollback_and_log(self, event: str, error: Exception, **context) -> None:
        await self._session.rollback()
        logger.exception(
            event,
            extra=_context(error_type=type(error).__name__, **context),
        )

    async def create(
        self,
        scan_id: str,
        cluster_id: str,
        scanner_type: str,
        status: str = SCAN_STATUS_CREATED,
        request_source: RequestSource = "manual",
        requested_at: datetime | None = None,
    ) -> ScanRecord:
        record_kwargs = dict(
            scan_id=scan_id,
            cluster_id=cluster_id,
            scanner_type=scanner_type,
            status=status,
            request_source=request_source,
        )
        if requested_at is not None:
            record_kwargs["requested_at"] = requested_at
        record = ScanRecord(**record_kwargs)
        self._session.add(record)
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="create",
                scan_id=scan_id,
                cluster_id=cluster_id,
                scanner_type=scanner_type,
                request_source=request_source,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="create",
                scan_id=scan_id,
                cluster_id=cluster_id,
                scanner_type=scanner_type,
                request_source=request_source,
            )
            raise

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
        if "completed_at" in kwargs:
            record.completed_at = kwargs["completed_at"]
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="update_status",
                scan_id=scan_id,
                status_after=status,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="update_status",
                scan_id=scan_id,
                status_after=status,
            )
            raise

    async def update(self, scan_id: str, status: str, s3_keys: list[str], completed_at=None) -> ScanRecord:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        record = result.scalars().first()
        record.status = status
        record.s3_keys = s3_keys
        if completed_at is not None:
            record.completed_at = completed_at
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="update",
                scan_id=scan_id,
                status_after=status,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="update",
                scan_id=scan_id,
                status_after=status,
            )
            raise

    async def update_files(self, scan_id: str, s3_keys: list[str]) -> ScanRecord:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        record = result.scalars().first()
        record.s3_keys = s3_keys
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="update_files",
                scan_id=scan_id,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="update_files",
                scan_id=scan_id,
            )
            raise

    async def list_by_cluster(self, cluster_id: str) -> list[ScanRecord]:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.cluster_id == str(cluster_id))
        )
        return list(result.scalars().all())

    async def get_latest_completed_scans(self, cluster_id: str) -> dict:
        # scan_records.cluster_id 가 VARCHAR 로 저장되어 있으므로 str 로 비교
        cluster_id_str = str(cluster_id)
        subq = (
            select(ScanRecord.scanner_type, func.max(ScanRecord.created_at).label("max_created_at"))
            .where(
                ScanRecord.cluster_id == cluster_id_str,
                ScanRecord.status == "completed",
            )
            .group_by(ScanRecord.scanner_type)
            .subquery()
        )
        result = await self._session.execute(
            select(ScanRecord).join(
                subq,
                (ScanRecord.scanner_type == subq.c.scanner_type) &
                (ScanRecord.created_at == subq.c.max_created_at),
            ).where(ScanRecord.cluster_id == cluster_id_str)
        )
        return {record.scanner_type: record for record in result.scalars().all()}

    async def find_active_scan(self, cluster_id: str, scanner_type: str) -> Optional[ScanRecord]:
        result = await self._session.execute(
            select(ScanRecord).where(
                ScanRecord.cluster_id == str(cluster_id),
                ScanRecord.scanner_type == scanner_type,
                ScanRecord.status.in_(ACTIVE_SCAN_STATUSES),
            )
        )
        return result.scalars().first()

    async def claim_next_queued_scan(
        self,
        cluster_id: str,
        scanner_type: str,
        claimed_by: str,
        lease_expires_at: datetime,
        started_at: datetime,
    ) -> Optional[ScanRecord]:
        result = await self._session.execute(
            select(ScanRecord)
            .where(
                ScanRecord.cluster_id == str(cluster_id),
                ScanRecord.scanner_type == scanner_type,
                ScanRecord.status == SCAN_STATUS_CREATED,
            )
            .order_by(ScanRecord.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        record = result.scalars().first()
        if record is None:
            return None
        record.status = SCAN_STATUS_PROCESSING
        record.claimed_by = claimed_by
        record.claimed_at = started_at
        record.started_at = started_at
        record.lease_expires_at = lease_expires_at
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="claim_next_queued_scan",
                scan_id=record.scan_id,
                cluster_id=record.cluster_id,
                scanner_type=record.scanner_type,
                status_after=SCAN_STATUS_PROCESSING,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="claim_next_queued_scan",
                scan_id=record.scan_id,
                cluster_id=record.cluster_id,
                scanner_type=record.scanner_type,
                status_after=SCAN_STATUS_PROCESSING,
            )
            raise

    async def set_analysis_run_id(self, scan_id: str, analysis_run_id: str) -> ScanRecord:
        result = await self._session.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        record = result.scalars().first()
        record.analysis_run_id = analysis_run_id
        try:
            await self._session.commit()
            await self._session.refresh(record)
            return record
        except IntegrityError as exc:
            await self._rollback_and_log(
                "scan.repository.integrity_error",
                exc,
                operation="set_analysis_run_id",
                scan_id=scan_id,
                analysis_run_id=analysis_run_id,
            )
            raise
        except SQLAlchemyError as exc:
            await self._rollback_and_log(
                "scan.repository.database_error",
                exc,
                operation="set_analysis_run_id",
                scan_id=scan_id,
                analysis_run_id=analysis_run_id,
            )
            raise
