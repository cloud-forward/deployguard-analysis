import re
import logging
from datetime import datetime, timedelta
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from app.application.services.scan_service import ScanService
from app.config import settings
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_CREATED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PROCESSING,
    SCAN_STATUS_UPLOADING,
)


def make_service():
    mock_repo = AsyncMock()
    mock_s3 = MagicMock()
    mock_clusters = AsyncMock()
    mock_s3.generate_presigned_upload_url.return_value = (
        "https://presigned-url", "scans/c1/s1/k8s/k8s-snapshot.json"
    )
    mock_s3.generate_presigned_download_url.return_value = "https://download-url"
    mock_s3.verify_file_exists.return_value = True
    mock_clusters.get_by_id.return_value = SimpleNamespace(id="prod-01", cluster_type="eks")
    mock_repo.list_active_scans.return_value = []
    mock_repo.find_active_scan.return_value = None
    svc = ScanService(scan_repository=mock_repo, s3_service=mock_s3, cluster_repository=mock_clusters)
    return svc, mock_repo, mock_s3, mock_clusters


class TestScanServiceStartScan:

    @pytest.mark.asyncio
    async def test_start_scan_returns_scan_id(self):
        """start_scan returns a scan_id and status=created"""
        svc, repo, _, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", request_source="manual")

        assert len(result.scans) == 2
        assert result.status == SCAN_STATUS_CREATED

    @pytest.mark.asyncio
    async def test_k8s_cluster_start_creates_k8s_and_image_records(self):
        svc, repo, _, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", request_source="manual")

        created_types = [scan.scanner_type for scan in result.scans]
        assert created_types == ["k8s", "image"]
        assert re.match(r"^\d{8}T\d{6}-k8s$", result.scans[0].scan_id)
        assert re.match(r"^\d{8}T\d{6}-image$", result.scans[1].scan_id)

    @pytest.mark.asyncio
    async def test_aws_cluster_start_creates_only_aws_record(self):
        svc, repo, _, clusters = make_service()
        repo.find_active_scan.return_value = None
        clusters.get_by_id.return_value = SimpleNamespace(id="prod-01", cluster_type="aws")

        result = await svc.start_scan("prod-01", "manual")

        repo.create.assert_called_once()
        _, kwargs = repo.create.call_args
        assert kwargs["status"] == SCAN_STATUS_CREATED
        assert kwargs["request_source"] == "manual"
        assert kwargs["scanner_type"] == "aws"
        assert kwargs["requested_at"] is not None
        assert [scan.scanner_type for scan in result.scans] == ["aws"]

    @pytest.mark.asyncio
    async def test_start_scan_passes_user_id_to_repository_create(self):
        svc, repo, _, clusters = make_service()
        repo.find_active_scan.return_value = None
        clusters.get_by_id.return_value = SimpleNamespace(id="prod-01", cluster_type="aws")

        await svc.start_scan("prod-01", "manual", user_id="user-1")

        repo.create.assert_called_once()
        _, kwargs = repo.create.call_args
        assert kwargs["user_id"] == "user-1"

    @pytest.mark.asyncio
    async def test_start_scan_duplicate_raises_409(self):
        """start_scan raises 409 if any fan-out scanner already has an active scan"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.find_active_scan.side_effect = [None, MagicMock(status=SCAN_STATUS_CREATED)]

        with pytest.raises(HTTPException) as exc_info:
            await svc.start_scan("prod-01", "manual")

        assert exc_info.value.status_code == 409
        assert "already running" in exc_info.value.detail
        repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_start_scan_duplicate_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.find_active_scan.side_effect = [MagicMock(status=SCAN_STATUS_CREATED)]

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await svc.start_scan(
                    "prod-01",
                    "manual",
                    request_id="req-dup-1",
                    endpoint_path="/api/v1/scans/start",
                )

        record = next(record for record in caplog.records if record.getMessage() == "scan.start.rejected_active_scan")
        assert record.request_id == "req-dup-1"
        assert record.cluster_id == "prod-01"
        assert record.scanner_type == "k8s"
        assert record.request_source == "manual"
        assert record.endpoint_path == "/api/v1/scans/start"
        assert record.error_type == "HTTPException"

    @pytest.mark.asyncio
    async def test_allow_new_scan_if_previous_completed(self):
        """start_scan succeeds when find_active_scan returns None (prior scan completed)"""
        svc, repo, _, _ = make_service()
        repo.find_active_scan.return_value = None  # completed scans are not active

        result = await svc.start_scan("prod-01", "manual")

        assert result.status == SCAN_STATUS_CREATED
        assert repo.create.call_count == 2

    @pytest.mark.asyncio
    async def test_allow_new_scan_if_previous_failed(self):
        """start_scan succeeds when find_active_scan returns None (prior scan failed)"""
        svc, repo, _, clusters = make_service()
        repo.find_active_scan.return_value = None
        clusters.get_by_id.return_value = SimpleNamespace(id="prod-01", cluster_type="aws")

        result = await svc.start_scan("prod-01", "manual")

        assert result.status == SCAN_STATUS_CREATED
        repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_scan_auto_fails_stale_created_scan(self):
        svc, repo, _, _ = make_service()
        stale = SimpleNamespace(
            scan_id="stale-created",
            cluster_id="prod-01",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
            requested_at=datetime.utcnow() - timedelta(seconds=settings.SCAN_CREATED_STALE_SECONDS + 5),
            created_at=datetime.utcnow() - timedelta(seconds=settings.SCAN_CREATED_STALE_SECONDS + 5),
            started_at=None,
            lease_expires_at=None,
        )
        repo.list_active_scans.return_value = [stale]

        await svc.start_scan("prod-01", "manual")

        repo.mark_failed.assert_awaited_once()
        assert repo.mark_failed.await_args.args[0] == "stale-created"

    @pytest.mark.asyncio
    async def test_start_scan_auto_fails_stale_processing_scan(self):
        svc, repo, _, _ = make_service()
        stale = SimpleNamespace(
            scan_id="stale-processing",
            cluster_id="prod-01",
            scanner_type="k8s",
            status=SCAN_STATUS_PROCESSING,
            requested_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow() - timedelta(minutes=10),
            lease_expires_at=datetime.utcnow() - timedelta(seconds=1),
        )
        repo.list_active_scans.return_value = [stale]

        await svc.start_scan("prod-01", "manual")

        repo.mark_failed.assert_awaited_once()
        assert repo.mark_failed.await_args.args[0] == "stale-processing"

    @pytest.mark.asyncio
    async def test_start_scan_auto_fails_stale_uploading_scan(self):
        svc, repo, _, _ = make_service()
        stale = SimpleNamespace(
            scan_id="stale-uploading",
            cluster_id="prod-01",
            scanner_type="image",
            status=SCAN_STATUS_UPLOADING,
            requested_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow() - timedelta(minutes=10),
            lease_expires_at=datetime.utcnow() - timedelta(seconds=1),
        )
        repo.list_active_scans.return_value = [stale]

        await svc.start_scan("prod-01", "manual")

        repo.mark_failed.assert_awaited_once()
        assert repo.mark_failed.await_args.args[0] == "stale-uploading"

    @pytest.mark.asyncio
    async def test_start_scan_auto_cleanup_ignores_terminal_scans(self):
        svc, repo, _, _ = make_service()
        completed = SimpleNamespace(
            scan_id="done-1",
            cluster_id="prod-01",
            scanner_type="k8s",
            status=SCAN_STATUS_COMPLETED,
        )
        failed = SimpleNamespace(
            scan_id="fail-1",
            cluster_id="prod-01",
            scanner_type="image",
            status=SCAN_STATUS_FAILED,
        )

        assert svc._stale_rule_for_record(completed, datetime.utcnow()) is None
        assert svc._stale_rule_for_record(failed, datetime.utcnow()) is None

    @pytest.mark.asyncio
    async def test_start_scan_stale_cleanup_logs_auto_fail(self, caplog):
        svc, repo, _, _ = make_service()
        stale = SimpleNamespace(
            scan_id="stale-created",
            cluster_id="prod-01",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
            requested_at=datetime.utcnow() - timedelta(seconds=settings.SCAN_CREATED_STALE_SECONDS + 5),
            created_at=datetime.utcnow() - timedelta(seconds=settings.SCAN_CREATED_STALE_SECONDS + 5),
            started_at=None,
            lease_expires_at=None,
        )
        repo.list_active_scans.return_value = [stale]

        with caplog.at_level(logging.WARNING):
            await svc.start_scan(
                "prod-01",
                "manual",
                request_id="req-stale-1",
                endpoint_path="/api/v1/scans/start",
            )

        record = next(record for record in caplog.records if record.getMessage() == "scan.stale.auto_failed")
        assert record.request_id == "req-stale-1"
        assert record.scan_id == "stale-created"
        assert record.status_before == SCAN_STATUS_CREATED
        assert record.status_after == SCAN_STATUS_FAILED
        assert record.stale_rule == "created_timeout"
        assert record.failure_source == "auto"
        assert record.trigger_endpoint == "/api/v1/scans/start"


class TestScanServiceUploadUrl:

    @pytest.mark.asyncio
    async def test_upload_url_returns_presigned_url(self):
        """get_upload_url returns S3 presigned URL and s3_key"""
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s", status=SCAN_STATUS_PROCESSING
        )

        result = await svc.get_upload_url("s1", "k8s_scan.json")

        assert "presigned-url" in result.upload_url
        assert result.s3_key == "scans/c1/s1/k8s/k8s-snapshot.json"

    @pytest.mark.asyncio
    async def test_upload_url_scan_not_found_raises_404(self):
        """get_upload_url raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("nonexistent", "f.json")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_upload_url_completed_scan_raises_409(self):
        """get_upload_url raises 409 for already completed scan"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="completed")

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_failed_scan_raises_409(self):
        """get_upload_url raises 409 for a failed scan"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="failed")

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_invalid_state_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
        )

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await svc.get_upload_url(
                    "s1",
                    "f.json",
                    request_id="req-upload-1",
                    endpoint_path="/api/v1/scans/s1/upload-url",
                )

        record = next(record for record in caplog.records if record.getMessage() == "scan.upload_url.invalid_state")
        assert record.request_id == "req-upload-1"
        assert record.scan_id == "s1"
        assert record.cluster_id == "c1"
        assert record.scanner_type == "k8s"
        assert record.status_before == SCAN_STATUS_CREATED
        assert record.endpoint_path == "/api/v1/scans/s1/upload-url"
        assert record.error_type == "HTTPException"

    @pytest.mark.asyncio
    async def test_upload_url_queued_scan_raises_409(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status=SCAN_STATUS_CREATED)

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_transitions_status_to_uploading(self):
        """get_upload_url updates status to 'uploading' when scan is 'processing'"""
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s", status=SCAN_STATUS_PROCESSING
        )

        await svc.get_upload_url("s1", "f.json")

        repo.update_status.assert_called_once_with("s1", SCAN_STATUS_UPLOADING)


class TestScanServiceComplete:

    @pytest.mark.asyncio
    async def test_complete_scan_returns_completed(self):
        """complete_scan returns status=completed on success"""
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        result = await svc.complete_scan("s1", ["scans/c1/s1/k8s/k8s-snapshot.json"])

        assert result.status == SCAN_STATUS_COMPLETED
        assert result.scan_id == "s1"

    @pytest.mark.asyncio
    async def test_complete_scan_calls_update(self):
        """complete_scan calls repository.update with status=completed"""
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        await svc.complete_scan("s1", ["scans/c1/s1/k8s/k8s-snapshot.json"])

        repo.update.assert_called_once()
        call_kwargs = repo.update.call_args
        assert call_kwargs[1]["status"] == SCAN_STATUS_COMPLETED
        assert call_kwargs[1]["completed_at"] is not None

    @pytest.mark.asyncio
    async def test_complete_scan_does_not_trigger_analysis_automatically(self):
        svc, repo, _, _ = make_service()
        analysis = AsyncMock()
        svc._analysis = analysis
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="uploading",
        )

        await svc.complete_scan("s1", ["scans/c1/s1/k8s/k8s-snapshot.json"])

        analysis.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_complete_scan_not_found_raises_404(self):
        """complete_scan raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("nonexistent", ["f.json"])

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_raises_400(self):
        """complete_scan raises 400 if a file is not found in S3"""
        from fastapi import HTTPException
        svc, repo, s3, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")
        s3.verify_file_exists.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/missing.json"])

        assert exc_info.value.status_code == 400
        repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_does_not_trigger_analysis(self):
        from fastapi import HTTPException
        svc, repo, s3, _ = make_service()
        analysis = AsyncMock()
        svc._analysis = analysis
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="uploading",
        )
        s3.verify_file_exists.return_value = False

        with pytest.raises(HTTPException):
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/missing.json"])

        analysis.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, s3, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="uploading",
        )
        s3.verify_file_exists.return_value = False

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await svc.complete_scan(
                    "s1",
                    ["scans/c1/s1/k8s/missing.json"],
                    authenticated_cluster_id="c1",
                    request_id="req-complete-1",
                    endpoint_path="/api/v1/scans/s1/complete",
                )

        record = next(record for record in caplog.records if record.getMessage() == "scan.complete.missing_s3_key")
        assert record.request_id == "req-complete-1"
        assert record.scan_id == "s1"
        assert record.cluster_id == "c1"
        assert record.scanner_type == "k8s"
        assert record.endpoint_path == "/api/v1/scans/s1/complete"
        assert record.error_type == "HTTPException"

    @pytest.mark.asyncio
    async def test_complete_scan_invalid_state_raises_409(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status=SCAN_STATUS_CREATED)

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/k8s-snapshot.json"])

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_complete_scan_ownership_mismatch_raises_403(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", cluster_id="c1", status="uploading")

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/k8s-snapshot.json"], authenticated_cluster_id="c2")

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_complete_scan_ownership_mismatch_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="uploading",
        )

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await svc.complete_scan(
                    "s1",
                    ["scans/c1/s1/k8s/k8s-snapshot.json"],
                    authenticated_cluster_id="c2",
                    request_id="req-owner-1",
                    endpoint_path="/api/v1/scans/s1/complete",
                )

        record = next(record for record in caplog.records if record.getMessage() == "scan.complete.ownership_mismatch")
        assert record.request_id == "req-owner-1"
        assert record.scan_id == "s1"
        assert record.cluster_id == "c1"
        assert record.scanner_type == "k8s"
        assert record.endpoint_path == "/api/v1/scans/s1/complete"
        assert record.error_type == "HTTPException"


class TestScanServiceGetStatus:

    @pytest.mark.asyncio
    async def test_get_status_returns_current_state(self):
        """get_scan_status returns current status and scan metadata"""
        from datetime import datetime
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s",
            status="completed",
            created_at=datetime(2024, 1, 15), completed_at=datetime(2024, 1, 15, 10, 30),
            s3_keys=["scans/c1/s1/k8s/k8s-snapshot.json"]
        )

        result = await svc.get_scan_status("s1")

        assert result.status == "completed"
        assert result.scan_id == "s1"

    @pytest.mark.asyncio
    async def test_get_status_passes_user_id_to_repository(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="created",
        )

        await svc.get_scan_status("s1", user_id="user-1")

        repo.get_by_scan_id.assert_awaited_with("s1", user_id="user-1")

    @pytest.mark.asyncio
    async def test_get_status_not_found_raises_404(self):
        """get_scan_status raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_scan_status("nonexistent")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_status_falls_back_to_requested_at_when_created_at_missing(self):
        from datetime import datetime
        svc, repo, _, _ = make_service()
        requested_at = datetime(2024, 1, 15, 10, 0, 0)
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="created",
            requested_at=requested_at,
        )

        result = await svc.get_scan_status("s1")

        assert result.created_at == requested_at
        assert result.completed_at is None
        assert result.files == []


class TestScanServiceGetDetail:

    @pytest.mark.asyncio
    async def test_get_detail_returns_scan_metadata(self):
        from datetime import datetime
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="completed",
            created_at=datetime(2024, 1, 15),
            completed_at=datetime(2024, 1, 15, 10, 30),
            s3_keys=["scans/c1/s1/k8s/k8s-snapshot.json"],
        )

        result = await svc.get_scan_detail("s1")

        assert result.scan_id == "s1"
        assert result.cluster_id == "c1"
        assert result.scanner_type == "k8s"
        assert result.status == "completed"
        assert result.s3_keys == ["scans/c1/s1/k8s/k8s-snapshot.json"]

    @pytest.mark.asyncio
    async def test_get_detail_passes_user_id_to_repository(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="created",
        )

        await svc.get_scan_detail("s1", user_id="user-1")

        repo.get_by_scan_id.assert_awaited_with("s1", user_id="user-1")

    @pytest.mark.asyncio
    async def test_get_detail_not_found_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_scan_detail("nonexistent")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_detail_falls_back_to_requested_at_and_empty_s3_keys(self):
        from datetime import datetime
        svc, repo, _, _ = make_service()
        requested_at = datetime(2024, 1, 15, 10, 0, 0)
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="aws",
            status="created",
            requested_at=requested_at,
        )

        result = await svc.get_scan_detail("s1")

        assert result.created_at == requested_at
        assert result.completed_at is None
        assert result.s3_keys == []


class TestScanServiceListClusterScans:

    @pytest.mark.asyncio
    async def test_list_cluster_scans_returns_newest_first(self):
        from datetime import datetime
        svc, repo, _, _ = make_service()
        repo.list_by_cluster.return_value = [
            MagicMock(
                scan_id="older",
                scanner_type="k8s",
                status="completed",
                created_at=datetime(2024, 1, 15, 10, 0, 0),
                completed_at=datetime(2024, 1, 15, 10, 30, 0),
                s3_keys=["scans/c1/older/k8s/k8s-snapshot.json"],
            ),
            MagicMock(
                scan_id="newer",
                scanner_type="aws",
                status=SCAN_STATUS_PROCESSING,
                created_at=datetime(2024, 1, 16, 10, 0, 0),
                completed_at=None,
                s3_keys=[],
            ),
        ]

        result = await svc.list_cluster_scans("c1")

        assert result.total == 2
        assert [item.scan_id for item in result.items] == ["newer", "older"]
        assert result.items[0].file_count == 0
        assert result.items[0].has_raw_result is False
        assert result.items[1].file_count == 1
        assert result.items[1].has_raw_result is True

    @pytest.mark.asyncio
    async def test_list_cluster_scans_passes_user_id_to_repository(self):
        svc, repo, _, _ = make_service()
        repo.list_by_cluster.return_value = []

        await svc.list_cluster_scans("c1", user_id="user-1")

        repo.list_by_cluster.assert_awaited_with("c1", user_id="user-1")

    @pytest.mark.asyncio
    async def test_list_cluster_scans_returns_empty_list(self):
        svc, repo, _, _ = make_service()
        repo.list_by_cluster.return_value = []

        result = await svc.list_cluster_scans("c1")

        assert result.total == 0
        assert result.items == []

    @pytest.mark.asyncio
    async def test_list_cluster_scans_uses_requested_at_when_created_at_missing(self):
        from datetime import datetime
        svc, repo, _, _ = make_service()
        older_requested_at = datetime(2024, 1, 15, 10, 0, 0)
        newer_requested_at = datetime(2024, 1, 16, 10, 0, 0)
        repo.list_by_cluster.return_value = [
            SimpleNamespace(
                scan_id="older",
                scanner_type="k8s",
                status="completed",
                requested_at=older_requested_at,
                completed_at=datetime(2024, 1, 15, 10, 30, 0),
                s3_keys=["scans/c1/older/k8s/k8s-snapshot.json"],
            ),
            SimpleNamespace(
                scan_id="newer",
                scanner_type="aws",
                status="created",
                requested_at=newer_requested_at,
            ),
        ]

        result = await svc.list_cluster_scans("c1")

        assert result.total == 2
        assert [item.scan_id for item in result.items] == ["newer", "older"]
        assert result.items[0].created_at == newer_requested_at
        assert result.items[0].file_count == 0
        assert result.items[1].created_at == older_requested_at
        assert result.items[1].file_count == 1


class TestScanServiceGetRawResultDownloadUrl:

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_returns_presigned_url(self):
        svc, repo, s3, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            s3_keys=["scans/c1/s1/k8s/k8s-snapshot.json"],
        )

        result = await svc.get_raw_result_download_url("s1")

        assert result.scan_id == "s1"
        assert result.s3_key == "scans/c1/s1/k8s/k8s-snapshot.json"
        assert result.download_url == "https://download-url"
        assert result.expires_in == 600
        s3.generate_presigned_download_url.assert_called_once_with(
            s3_key="scans/c1/s1/k8s/k8s-snapshot.json",
            expires_in=600,
        )

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_not_found_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_raw_result_download_url("nonexistent")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_without_files_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            s3_keys=[],
        )

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_raw_result_download_url("s1")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_multiple_files_raises_409(self):
        from fastapi import HTTPException
        svc, repo, s3, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            s3_keys=[
                "scans/c1/s1/k8s/k8s-snapshot.json",
                "scans/c1/s1/k8s/extra.json",
            ],
        )

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_raw_result_download_url("s1")

        assert exc_info.value.status_code == 409
        s3.generate_presigned_download_url.assert_not_called()


class TestScanServiceClaimPending:

    @pytest.mark.asyncio
    async def test_claim_pending_scan_calls_repo(self):
        svc, repo, _, _ = make_service()
        repo.claim_next_queued_scan.return_value = MagicMock(scan_id="s1")

        result = await svc.claim_pending_scan(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_seconds=300,
        )

        assert result.scan_id == "s1"
        repo.claim_next_queued_scan.assert_called_once()


class TestScanServiceFailScan:

    @pytest.mark.asyncio
    async def test_fail_scan_marks_created_as_failed(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
        )

        result = await svc.fail_scan("s1")

        assert result.status == SCAN_STATUS_FAILED
        repo.mark_failed.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fail_scan_passes_user_id_through(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
        )

        await svc.fail_scan("s1", user_id="user-1")

        repo.get_by_scan_id.assert_awaited_with("s1", user_id="user-1")
        assert repo.mark_failed.await_args.kwargs["user_id"] == "user-1"

    @pytest.mark.asyncio
    async def test_fail_scan_marks_processing_as_failed(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_PROCESSING,
        )

        result = await svc.fail_scan("s1")

        assert result.status == SCAN_STATUS_FAILED
        repo.mark_failed.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fail_scan_marks_uploading_as_failed(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_UPLOADING,
        )

        result = await svc.fail_scan("s1")

        assert result.status == SCAN_STATUS_FAILED
        repo.mark_failed.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fail_scan_completed_is_idempotent(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_COMPLETED,
        )

        result = await svc.fail_scan("s1")

        assert result.status == SCAN_STATUS_COMPLETED
        repo.mark_failed.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_fail_scan_failed_is_idempotent(self):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_FAILED,
        )

        result = await svc.fail_scan("s1")

        assert result.status == SCAN_STATUS_FAILED
        repo.mark_failed.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_fail_scan_logs_accepted(self, caplog):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_CREATED,
        )

        with caplog.at_level(logging.INFO):
            await svc.fail_scan("s1", request_id="req-fail-1", endpoint_path="/api/v1/scans/s1/fail")

        record = next(record for record in caplog.records if record.getMessage() == "scan.fail.accepted")
        assert record.request_id == "req-fail-1"
        assert record.scan_id == "s1"
        assert record.status_before == SCAN_STATUS_CREATED
        assert record.status_after == SCAN_STATUS_FAILED
        assert record.failure_source == "manual"

    @pytest.mark.asyncio
    async def test_fail_scan_logs_already_terminal(self, caplog):
        svc, repo, _, _ = make_service()
        repo.get_by_scan_id.return_value = SimpleNamespace(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status=SCAN_STATUS_COMPLETED,
        )

        with caplog.at_level(logging.INFO):
            await svc.fail_scan("s1", request_id="req-fail-2", endpoint_path="/api/v1/scans/s1/fail")

        record = next(record for record in caplog.records if record.getMessage() == "scan.fail.already_terminal")
        assert record.request_id == "req-fail-2"
        assert record.scan_id == "s1"
        assert record.status_before == SCAN_STATUS_COMPLETED
        assert record.status_after == SCAN_STATUS_COMPLETED
