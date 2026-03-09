"""
Application service for scan session management.
Coordinates the 3-step scan flow: start → upload → complete.
"""
from __future__ import annotations
import logging
from datetime import datetime
from fastapi import HTTPException
from app.core.constants import (
    SCAN_STATUS_CREATED,
    SCAN_STATUS_UPLOADING,
    SCAN_STATUS_PROCESSING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
)
from app.models.schemas import (
    ScanCompleteResponse,
    ScanStartResponse,
    ScanStatusResponse,
    UploadUrlResponse,
)
logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, scan_repository, s3_service):
        """
        scan_repository: handles DB persistence for ScanRecord
        s3_service: handles S3 presigned URL generation
        """
        self._repo = scan_repository
        self._s3 = s3_service

    async def start_scan(self, cluster_id: str, scanner_type: str) -> ScanStartResponse:
        """
        1. Generate scan_id ({timestamp}-{scanner_type})
        2. Create ScanRecord in DB with status="created"
        3. Return scan_id
        """
        active = await self._repo.find_active_scan(cluster_id, scanner_type)
        if active is not None:
            raise HTTPException(
                status_code=409,
                detail="A scan for this cluster and scanner type is already running",
            )
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        scan_id = f"{timestamp}-{scanner_type}"
        await self._repo.create(scan_id=scan_id, cluster_id=cluster_id, scanner_type=scanner_type)
        logger.info("Scan session created: scan_id=%s cluster_id=%s scanner_type=%s", scan_id, cluster_id, scanner_type)
        return ScanStartResponse(scan_id=scan_id, status=SCAN_STATUS_CREATED)

    async def get_upload_url(self, scan_id: str, file_name: str) -> UploadUrlResponse:
        """
        1. Look up ScanRecord by scan_id
        2. If not found → raise HTTPException 404
        3. If status is "completed" or "failed" → raise HTTPException 409
        4. Generate presigned URL via S3Service
           S3 key layout: scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}
        5. Update status to "uploading" if still "created"
        6. Return upload_url and s3_key
        """
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        if record.status in (SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED):
            raise HTTPException(
                status_code=409,
                detail=f"Scan session is already {record.status} and cannot accept uploads",
            )
        upload_url, s3_key = self._s3.generate_presigned_upload_url(
            cluster_id=record.cluster_id,
            scan_id=scan_id,
            scanner_type=record.scanner_type,
            file_name=file_name,
        )
        if record.status == SCAN_STATUS_CREATED:
            await self._repo.update_status(scan_id, SCAN_STATUS_UPLOADING)
        logger.info("Presigned upload URL generated: scan_id=%s s3_key=%s", scan_id, s3_key)
        return UploadUrlResponse(upload_url=upload_url, s3_key=s3_key)

    async def complete_scan(self, scan_id: str, files: list[str]) -> ScanCompleteResponse:
        """
        1. Look up ScanRecord by scan_id
        2. If not found → raise HTTPException 404
        3. Optionally verify files exist in S3 (s3_service.verify_file_exists)
           - If any file missing → raise HTTPException 400 with details
        4. Update ScanRecord: status="processing", s3_keys=files, completed_at=now
        5. Trigger analysis (placeholder for now)
        6. Return status="processing"
        """
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        missing = [key for key in files if not self._s3.verify_file_exists(key)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"The following files were not found in S3: {missing}",
            )
        await self._repo.update(
            scan_id,
            status=SCAN_STATUS_PROCESSING,
            s3_keys=files,
            completed_at=datetime.utcnow(),
        )
        logger.info("Analysis triggered for scan %s", scan_id)
        return ScanCompleteResponse(scan_id=scan_id, status=SCAN_STATUS_PROCESSING)

    async def get_scan_status(self, scan_id: str) -> ScanStatusResponse:
        """
        Look up ScanRecord and return current status.
        If not found → raise HTTPException 404
        """
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
