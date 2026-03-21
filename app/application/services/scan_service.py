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
from app.models.schemas import ScannerType, RequestSource
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_UPLOADING,
)
from app.models.schemas import (
    ClusterScanListResponse,
    RawScanResultUrlResponse,
    ScanSummaryItemResponse,
    ScanCompleteResponse,
    ScanDetailResponse,
    ScanStartResponse,
    ScanStatusResponse,
    UploadUrlResponse,
)
logger = logging.getLogger(__name__)


def _context(**kwargs):
    return {key: value for key, value in kwargs.items() if value is not None}


def _error_type(error) -> str:
    return type(error).__name__


def _get_record_created_at(record) -> datetime:
    """Prefer persisted creation time, but support older/incomplete record shapes."""
    created_at = getattr(record, "created_at", None)
    if created_at is not None:
        return created_at

    requested_at = getattr(record, "requested_at", None)
    if requested_at is not None:
        return requested_at

    updated_at = getattr(record, "updated_at", None)
    if updated_at is not None:
        return updated_at

    completed_at = getattr(record, "completed_at", None)
    if completed_at is not None:
        return completed_at

    scan_id = getattr(record, "scan_id", None)
    logger.warning(
        "scan.serialization.missing_created_at",
        extra=_context(scan_id=scan_id),
    )
    return datetime.utcnow()


def _get_record_completed_at(record):
    return getattr(record, "completed_at", None)


def _get_record_s3_keys(record) -> list[str]:
    s3_keys = getattr(record, "s3_keys", None)
    return list(s3_keys or [])


class ScanService:
    def __init__(self, scan_repository, s3_service, analysis_service=None):
        self._repo = scan_repository
        self._s3 = s3_service
        self._analysis = analysis_service

    async def start_scan(
        self,
        cluster_id: UUID,
        scanner_type: ScannerType,
        request_source: RequestSource,
        request_id: str | None = None,
        endpoint_path: str | None = None,
    ) -> ScanStartResponse:
        cluster_id_str = str(cluster_id)
        scanner_type_str = scanner_type.value if isinstance(scanner_type, ScannerType) else str(scanner_type)
        requested_at = datetime.utcnow()
        active = await self._repo.find_active_scan(cluster_id_str, scanner_type_str)
        if active is not None:
            error = HTTPException(
                status_code=409,
                detail="A scan for this cluster and scanner type is already running",
            )
            logger.warning(
                "scan.start.rejected_active_scan",
                extra=_context(
                    request_id=request_id,
                    cluster_id=cluster_id_str,
                    scanner_type=scanner_type_str,
                    request_source=request_source,
                    endpoint_path=endpoint_path,
                    error_type=_error_type(error),
                ),
            )
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
        logger.info(
            "scan.start.record_created",
            extra=_context(
                request_id=request_id,
                scan_id=scan_id,
                cluster_id=cluster_id_str,
                scanner_type=scanner_type_str,
                request_source=request_source,
                status_after=SCAN_STATUS_QUEUED,
            ),
        )
        return ScanStartResponse(scan_id=scan_id, status=SCAN_STATUS_QUEUED)

    async def get_upload_url(
        self,
        scan_id: str,
        file_name: str,
        request_id: str | None = None,
        endpoint_path: str | None = None,
    ) -> UploadUrlResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            error = HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
            logger.warning(
                "scan.upload_url.not_found",
                extra=_context(
                    request_id=request_id,
                    scan_id=scan_id,
                    endpoint_path=endpoint_path,
                    error_type=_error_type(error),
                ),
            )
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        status_before = record.status
        if record.status not in (SCAN_STATUS_RUNNING, SCAN_STATUS_UPLOADING):
            error = HTTPException(
                status_code=409,
                detail=f"Scan session is {record.status} and cannot accept uploads",
            )
            logger.warning(
                "scan.upload_url.invalid_state",
                extra=_context(
                    request_id=request_id,
                    scan_id=scan_id,
                    cluster_id=record.cluster_id,
                    scanner_type=record.scanner_type,
                    endpoint_path=endpoint_path,
                    status_before=record.status,
                    error_type=_error_type(error),
                ),
            )
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
            status_after = SCAN_STATUS_UPLOADING
        else:
            status_after = record.status
        logger.info(
            "scan.upload_url.generated",
            extra=_context(
                request_id=request_id,
                scan_id=scan_id,
                cluster_id=record.cluster_id,
                scanner_type=record.scanner_type,
                status_before=status_before,
                status_after=status_after,
            ),
        )
        return UploadUrlResponse(upload_url=upload_url, s3_key=s3_key)

    async def complete_scan(
        self,
        scan_id: str,
        files: list[str],
        authenticated_cluster_id: str | None = None,
        request_id: str | None = None,
        endpoint_path: str | None = None,
    ) -> ScanCompleteResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            error = HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
            logger.warning(
                "scan.complete.not_found",
                extra=_context(
                    request_id=request_id,
                    scan_id=scan_id,
                    endpoint_path=endpoint_path,
                    error_type=_error_type(error),
                ),
            )
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        if authenticated_cluster_id is not None and record.cluster_id != authenticated_cluster_id:
            error = HTTPException(status_code=403, detail="Scan does not belong to authenticated cluster")
            logger.warning(
                "scan.complete.ownership_mismatch",
                extra=_context(
                    request_id=request_id,
                    scan_id=scan_id,
                    cluster_id=record.cluster_id,
                    scanner_type=getattr(record, "scanner_type", None),
                    endpoint_path=endpoint_path,
                    error_type=_error_type(error),
                ),
            )
            raise HTTPException(status_code=403, detail="Scan does not belong to authenticated cluster")
        if record.status not in (SCAN_STATUS_RUNNING, SCAN_STATUS_UPLOADING):
            error = HTTPException(
                status_code=409,
                detail=f"Scan session is {record.status} and cannot be completed",
            )
            logger.warning(
                "scan.complete.invalid_state",
                extra=_context(
                    request_id=request_id,
                    scan_id=scan_id,
                    cluster_id=record.cluster_id,
                    scanner_type=record.scanner_type,
                    endpoint_path=endpoint_path,
                    status_before=record.status,
                    error_type=_error_type(error),
                ),
            )
            raise HTTPException(
                status_code=409,
                detail=f"Scan session is {record.status} and cannot be completed",
            )
        for f in files:
            if not self._s3.verify_file_exists(f):
                error = HTTPException(status_code=400, detail=f"File not found in S3: {f}")
                logger.warning(
                    "scan.complete.missing_s3_key",
                    extra=_context(
                        request_id=request_id,
                        scan_id=scan_id,
                        cluster_id=record.cluster_id,
                        scanner_type=record.scanner_type,
                        endpoint_path=endpoint_path,
                        error_type=_error_type(error),
                    ),
                )
                raise HTTPException(status_code=400, detail=f"File not found in S3: {f}")
        status_before = record.status
        completed_at = datetime.utcnow()
        await self._repo.update(
            scan_id,
            status=SCAN_STATUS_COMPLETED,
            s3_keys=files,
            completed_at=completed_at,
        )
        logger.info(
            "scan.complete.accepted",
            extra=_context(
                request_id=request_id,
                scan_id=scan_id,
                cluster_id=record.cluster_id,
                scanner_type=record.scanner_type,
                status_before=status_before,
                status_after=SCAN_STATUS_COMPLETED,
            ),
        )
        if self._analysis is not None:
            await self._analysis.maybe_trigger_analysis(record.cluster_id, request_id=request_id)
        return ScanCompleteResponse(scan_id=scan_id, status=SCAN_STATUS_COMPLETED)

    async def get_scan_status(self, scan_id: str) -> ScanStatusResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        return ScanStatusResponse(
            scan_id=record.scan_id,
            cluster_id=record.cluster_id,
            scanner_type=record.scanner_type,
            status=record.status,
            created_at=_get_record_created_at(record),
            completed_at=_get_record_completed_at(record),
            files=_get_record_s3_keys(record),
        )

    async def get_scan_detail(self, scan_id: str) -> ScanDetailResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")
        return ScanDetailResponse(
            scan_id=record.scan_id,
            cluster_id=record.cluster_id,
            scanner_type=record.scanner_type,
            status=record.status,
            created_at=_get_record_created_at(record),
            completed_at=_get_record_completed_at(record),
            s3_keys=_get_record_s3_keys(record),
        )

    async def list_cluster_scans(self, cluster_id: str) -> ClusterScanListResponse:
        records = await self._repo.list_by_cluster(cluster_id)
        ordered_records = sorted(records, key=_get_record_created_at, reverse=True)
        items = [
            ScanSummaryItemResponse(
                scan_id=record.scan_id,
                scanner_type=record.scanner_type,
                status=record.status,
                created_at=_get_record_created_at(record),
                completed_at=_get_record_completed_at(record),
                file_count=len(_get_record_s3_keys(record)),
                has_raw_result=bool(_get_record_s3_keys(record)),
            )
            for record in ordered_records
        ]
        return ClusterScanListResponse(items=items, total=len(items))

    async def get_raw_result_download_url(
        self,
        scan_id: str,
        expires_in: int = 600,
    ) -> RawScanResultUrlResponse:
        record = await self._repo.get_by_scan_id(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan session not found: {scan_id}")

        s3_keys = _get_record_s3_keys(record)
        if not s3_keys:
            raise HTTPException(status_code=404, detail=f"No raw scan result files found for scan: {scan_id}")
        if len(s3_keys) > 1:
            raise HTTPException(
                status_code=409,
                detail="Scan has multiple raw result files and no primary file selection rule is defined",
            )

        s3_key = s3_keys[0]
        download_url = self._s3.generate_presigned_download_url(s3_key=s3_key, expires_in=expires_in)
        return RawScanResultUrlResponse(
            scan_id=record.scan_id,
            s3_key=s3_key,
            download_url=download_url,
            expires_in=expires_in,
        )

    async def claim_pending_scan(
        self,
        cluster_id: str,
        scanner_type: ScannerType,
        claimed_by: str | None,
        lease_seconds: int,
        request_id: str | None = None,
    ):
        cluster_id_str = str(cluster_id)
        scanner_type_str = scanner_type.value if isinstance(scanner_type, ScannerType) else str(scanner_type)
        started_at = datetime.utcnow()
        lease_expires_at = started_at + timedelta(seconds=lease_seconds)
        claimed_by_value = claimed_by or "unknown-worker"
        record = await self._repo.claim_next_queued_scan(
            cluster_id=cluster_id_str,
            scanner_type=scanner_type_str,
            claimed_by=claimed_by_value,
            lease_expires_at=lease_expires_at,
            started_at=started_at,
        )
        if record is None:
            logger.info(
                "scan.pending.no_work_found",
                extra=_context(
                    request_id=request_id,
                    cluster_id=cluster_id_str,
                    scanner_type=scanner_type_str,
                    claimed_by=claimed_by_value,
                ),
            )
            return None
        logger.info(
            "scan.pending.claimed",
            extra=_context(
                request_id=request_id,
                scan_id=record.scan_id,
                cluster_id=record.cluster_id,
                scanner_type=record.scanner_type,
                claimed_by=record.claimed_by,
                status_before=SCAN_STATUS_QUEUED,
                status_after=SCAN_STATUS_RUNNING,
            ),
        )
        return record
