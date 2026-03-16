"""
Application service for scan session management.
Coordinates the 3-step scan flow: start → upload → complete.
"""
from __future__ import annotations
import logging
from datetime import datetime
from datetime import timedelta
from uuid import UUID
from fastapi import HTTPException
from app.models.schemas import ScannerType
from app.core.constants import (
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_UPLOADING,
    SCAN_STATUS_PROCESSING,
)
from app.models.schemas import (
    ScanCompleteResponse,
    ScanStartResponse,
    ScanStatusResponse,
    UploadUrlResponse,
)
logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, scan_repository, s3_service, analysis_service=None):
        self._repo = scan_repository
        self._s3 = s3_service
        self._analysis = analysis_service

    async def start_scan(self, cluster_id: UUID, scanner_type: ScannerType, request_source: str) -> ScanStartResponse:
        cluster_id_str = str(cluster_id)
        scanner_type_str = scanner_type.value if isinstance(scanner_type, ScannerType) else str(scanner_type)
        requested_at = datetime.utcnow()
        active = await self._repo.find_active_scan(cluster_id_str, scanner_type_str)
        if active is not None:
            raise HTTPException(
                status_code=409,
                detail="A scan for this cluster and scanner type is already running",
            )
        timestamp = requested_at.strftime("%Y%m%dT%H%M%S")
        scan_id = f"{timestamp}-{scanner_type_str}"
        await self._repo.create(
            scan_id=scan_id,
            cluster_id=cluster_id_str,
            scanner_type=scanner_type_str,
            status=SCAN_STATUS_QUEUED,
            request_source=request_source,
            requested_at=requested_at,
        )
        logger.info("Scan session created: scan_id=%s cluster_id=%s scanner_type=%s", scan_id, cluster_id_str, scanner_type_str)
        return ScanStartResponse(scan_id=scan_id, status=SCAN_STATUS_QUEUED)

    async def get_upload_url(self, scan_id: str, file_name: str) -> UploadUrlResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        if record.status not in (SCAN_STATUS_RUNNING, SCAN_STATUS_UPLOADING):
            raise HTTPException(
                status_code=409,
                detail=f"Scan session is {record.status} and cannot accept uploads",
            )
        upload_url, s3_key = self._s3.generate_presigned_upload_url(
            cluster_id=record.cluster_id,
            scan_id=scan_id,
            scanner_type=record.scanner_type,
            file_name=file_name,
        )
        if record.status == SCAN_STATUS_RUNNING:
            await self._repo.update_status(scan_id, SCAN_STATUS_UPLOADING)
            logger.info("Scan status updated to uploading: scan_id=%s", scan_id)
        return UploadUrlResponse(upload_url=upload_url, s3_key=s3_key)

    async def complete_scan(self, scan_id: str, files: list[str]) -> ScanCompleteResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        if record.status not in (SCAN_STATUS_RUNNING, SCAN_STATUS_UPLOADING):
            raise HTTPException(
                status_code=409,
                detail=f"Scan session is {record.status} and cannot be completed",
            )
        for f in files:
            if not self._s3.verify_file_exists(f):
                raise HTTPException(status_code=400, detail=f"File not found in S3: {f}")
        await self._repo.update(scan_id, status=SCAN_STATUS_PROCESSING, s3_keys=files)
        logger.info("Scan marked processing: scan_id=%s cluster_id=%s", scan_id, record.cluster_id)
        if self._analysis is not None:
            await self._analysis.maybe_trigger_analysis(record.cluster_id)
        return ScanCompleteResponse(scan_id=scan_id, status=SCAN_STATUS_PROCESSING)

    async def get_scan_status(self, scan_id: str) -> ScanStatusResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        return ScanStatusResponse(
            scan_id=record.scan_id,
            cluster_id=record.cluster_id,
            scanner_type=record.scanner_type,
            status=record.status,
            created_at=record.created_at,
            completed_at=record.completed_at,
            files=record.s3_keys or [],
        )

    async def claim_pending_scan(
        self,
        cluster_id: UUID,
        scanner_type: ScannerType,
        claimed_by: str,
        lease_seconds: int,
    ):
        cluster_id_str = str(cluster_id)
        scanner_type_str = scanner_type.value if isinstance(scanner_type, ScannerType) else str(scanner_type)
        started_at = datetime.utcnow()
        lease_expires_at = started_at + timedelta(seconds=lease_seconds)
        return await self._repo.claim_next_queued_scan(
            cluster_id=cluster_id_str,
            scanner_type=scanner_type_str,
            claimed_by=claimed_by,
            lease_expires_at=lease_expires_at,
            started_at=started_at,
        )
