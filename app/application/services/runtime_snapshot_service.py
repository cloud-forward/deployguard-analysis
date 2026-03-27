"""
Application service for runtime snapshot direct uploads.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

from fastapi import HTTPException

from app.config import settings
from app.domain.repositories.cluster_repository import ClusterRepository
from app.domain.repositories.runtime_snapshot_repository import RuntimeSnapshotRepository
from app.models.schemas import (
    RuntimeCompleteResponse,
    RuntimeStatusResponse,
    RuntimeUploadUrlResponse,
)


_RUNTIME_KEY_PATTERN = re.compile(
    r"^runtime/(?P<cluster_id>[^/]+)/(?P<timestamp>\d{8}T\d{6}Z)/events\.json$"
)


class RuntimeSnapshotService:
    def __init__(
        self,
        runtime_snapshot_repository: RuntimeSnapshotRepository,
        cluster_repository: ClusterRepository,
        s3_service,
    ):
        self._repo = runtime_snapshot_repository
        self._clusters = cluster_repository
        self._s3 = s3_service

    async def get_upload_url(self, authenticated_cluster_id: str) -> RuntimeUploadUrlResponse:
        uploaded_at = datetime.now(timezone.utc)
        upload_url, s3_key = self._s3.generate_runtime_presigned_upload_url(
            cluster_id=authenticated_cluster_id,
            uploaded_at=uploaded_at,
            expires_in=600,
        )
        return RuntimeUploadUrlResponse(
            upload_url=upload_url,
            s3_key=s3_key,
            expires_in=600,
        )

    async def complete_upload(
        self,
        authenticated_cluster_id: str,
        s3_key: str,
        snapshot_at: datetime,
        fact_count: int | None,
    ) -> RuntimeCompleteResponse:
        self._validate_runtime_s3_key(authenticated_cluster_id, s3_key)

        if not self._s3.verify_file_exists(s3_key):
            raise HTTPException(status_code=400, detail="Runtime snapshot object not found in S3")

        uploaded_at = datetime.now(timezone.utc)
        snapshot = await self._repo.create(
            cluster_id=authenticated_cluster_id,
            s3_key=s3_key,
            snapshot_at=snapshot_at,
            uploaded_at=uploaded_at,
            fact_count=fact_count,
        )
        return RuntimeCompleteResponse(
            upload_id=snapshot.id,
            cluster_id=snapshot.cluster_id,
            s3_key=snapshot.s3_key,
            snapshot_at=snapshot.snapshot_at,
            uploaded_at=snapshot.uploaded_at,
            fact_count=snapshot.fact_count,
        )

    async def get_status(self, cluster_id: str, user_id: str) -> RuntimeStatusResponse:
        cluster = await self._clusters.get_by_id(cluster_id, user_id=user_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        latest = await self._repo.get_latest_by_cluster_id(cluster_id)
        if latest is None:
            return RuntimeStatusResponse(
                cluster_id=cluster_id,
                last_uploaded_at=None,
                snapshot_at=None,
                fact_count=None,
                is_stale=True,
            )

        now = datetime.now(timezone.utc)
        stale_after = now - timedelta(seconds=settings.RUNTIME_STALE_THRESHOLD_SECONDS)
        uploaded_at = self._ensure_utc(latest.uploaded_at)
        return RuntimeStatusResponse(
            cluster_id=cluster_id,
            last_uploaded_at=uploaded_at,
            snapshot_at=self._ensure_utc(latest.snapshot_at),
            fact_count=latest.fact_count,
            is_stale=uploaded_at <= stale_after,
        )

    @staticmethod
    def _validate_runtime_s3_key(cluster_id: str, s3_key: str) -> None:
        match = _RUNTIME_KEY_PATTERN.fullmatch(s3_key)
        if match is None or match.group("cluster_id") != cluster_id:
            raise HTTPException(status_code=400, detail="s3_key does not belong to the authenticated cluster")

    @staticmethod
    def _ensure_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
