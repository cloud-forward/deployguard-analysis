import re
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.application.services.scan_service import ScanService


def make_service():
    mock_repo = AsyncMock()
    mock_s3 = MagicMock()
    mock_s3.generate_presigned_upload_url.return_value = (
        "https://presigned-url", "scans/c1/s1/k8s/f.json"
    )
    mock_s3.generate_presigned_download_url.return_value = "https://download-url"
    mock_s3.verify_file_exists.return_value = True
    svc = ScanService(scan_repository=mock_repo, s3_service=mock_s3)
    return svc, mock_repo, mock_s3


class TestScanServiceStartScan:

    @pytest.mark.asyncio
    async def test_start_scan_returns_scan_id(self):
        """start_scan returns a scan_id and status=queued"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", scanner_type="k8s", request_source="manual")

        assert result.scan_id is not None
        assert result.status == "queued"

    @pytest.mark.asyncio
    async def test_scan_id_format(self):
        """scan_id format must be {YYYYMMDDTHHmmSS}-{scanner_type}"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", scanner_type="k8s", request_source="manual")

        assert re.match(r"^\d{8}T\d{6}-k8s$", result.scan_id), (
            f"scan_id '{result.scan_id}' does not match expected format"
        )

    @pytest.mark.asyncio
    async def test_start_scan_creates_db_record(self):
        """start_scan calls repository.create exactly once"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        await svc.start_scan("prod-01", "k8s", "manual")

        repo.create.assert_called_once()
        _, kwargs = repo.create.call_args
        assert kwargs["status"] == "queued"
        assert kwargs["request_source"] == "manual"
        assert kwargs["scanner_type"] == "k8s"

    @pytest.mark.asyncio
    async def test_start_scan_duplicate_raises_409(self):
        """start_scan raises 409 if an active scan already exists"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = MagicMock(status="queued")

        with pytest.raises(HTTPException) as exc_info:
            await svc.start_scan("prod-01", "k8s", "manual")

        assert exc_info.value.status_code == 409
        assert "already running" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_start_scan_duplicate_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = MagicMock(status="queued")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await svc.start_scan(
                    "prod-01",
                    "k8s",
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
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None  # completed scans are not active

        result = await svc.start_scan("prod-01", "k8s", "manual")

        assert result.status == "queued"
        repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_allow_new_scan_if_previous_failed(self):
        """start_scan succeeds when find_active_scan returns None (prior scan failed)"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None  # failed scans are not active

        result = await svc.start_scan("prod-01", "aws", "manual")

        assert result.status == "queued"
        repo.create.assert_called_once()


class TestScanServiceUploadUrl:

    @pytest.mark.asyncio
    async def test_upload_url_returns_presigned_url(self):
        """get_upload_url returns S3 presigned URL and s3_key"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s", status="running"
        )

        result = await svc.get_upload_url("s1", "k8s_scan.json")

        assert "presigned-url" in result.upload_url
        assert result.s3_key == "scans/c1/s1/k8s/f.json"

    @pytest.mark.asyncio
    async def test_upload_url_scan_not_found_raises_404(self):
        """get_upload_url raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("nonexistent", "f.json")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_upload_url_completed_scan_raises_409(self):
        """get_upload_url raises 409 for already completed scan"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="completed")

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_failed_scan_raises_409(self):
        """get_upload_url raises 409 for a failed scan"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="failed")

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_invalid_state_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="queued",
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
        assert record.status_before == "queued"
        assert record.endpoint_path == "/api/v1/scans/s1/upload-url"
        assert record.error_type == "HTTPException"

    @pytest.mark.asyncio
    async def test_upload_url_queued_scan_raises_409(self):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="queued")

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_upload_url("s1", "f.json")

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_upload_url_transitions_status_to_uploading(self):
        """get_upload_url updates status to 'uploading' when scan is 'running'"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s", status="running"
        )

        await svc.get_upload_url("s1", "f.json")

        repo.update_status.assert_called_once_with("s1", "uploading")


class TestScanServiceComplete:

    @pytest.mark.asyncio
    async def test_complete_scan_returns_completed(self):
        """complete_scan returns status=completed on success"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        result = await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        assert result.status == "completed"
        assert result.scan_id == "s1"

    @pytest.mark.asyncio
    async def test_complete_scan_calls_update(self):
        """complete_scan calls repository.update with status=completed"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        repo.update.assert_called_once()
        call_kwargs = repo.update.call_args
        assert call_kwargs[1]["status"] == "completed"
        assert call_kwargs[1]["completed_at"] is not None

    @pytest.mark.asyncio
    async def test_complete_scan_triggers_analysis_check(self):
        svc, repo, _ = make_service()
        analysis = AsyncMock()
        svc._analysis = analysis
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="uploading",
        )

        await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        analysis.maybe_trigger_analysis.assert_awaited_once_with("c1", request_id=None)

    @pytest.mark.asyncio
    async def test_complete_scan_not_found_raises_404(self):
        """complete_scan raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("nonexistent", ["f.json"])

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_raises_400(self):
        """complete_scan raises 400 if a file is not found in S3"""
        from fastapi import HTTPException
        svc, repo, s3 = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")
        s3.verify_file_exists.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/missing.json"])

        assert exc_info.value.status_code == 400
        repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_does_not_trigger_analysis(self):
        from fastapi import HTTPException
        svc, repo, s3 = make_service()
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

        analysis.maybe_trigger_analysis.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_scan_missing_file_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, s3 = make_service()
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
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="queued")

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_complete_scan_ownership_mismatch_raises_403(self):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", cluster_id="c1", status="uploading")

        with pytest.raises(HTTPException) as exc_info:
            await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"], authenticated_cluster_id="c2")

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_complete_scan_ownership_mismatch_logs_failure_context(self, caplog):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
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
                    ["scans/c1/s1/k8s/f.json"],
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
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s",
            status="completed",
            created_at=datetime(2024, 1, 15), completed_at=datetime(2024, 1, 15, 10, 30),
            s3_keys=["scans/c1/s1/k8s.json"]
        )

        result = await svc.get_scan_status("s1")

        assert result.status == "completed"
        assert result.scan_id == "s1"

    @pytest.mark.asyncio
    async def test_get_status_not_found_raises_404(self):
        """get_scan_status raises 404 for unknown scan_id"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_scan_status("nonexistent")

        assert exc_info.value.status_code == 404


class TestScanServiceGetDetail:

    @pytest.mark.asyncio
    async def test_get_detail_returns_scan_metadata(self):
        from datetime import datetime
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            cluster_id="c1",
            scanner_type="k8s",
            status="completed",
            created_at=datetime(2024, 1, 15),
            completed_at=datetime(2024, 1, 15, 10, 30),
            s3_keys=["scans/c1/s1/k8s/scan.json"],
        )

        result = await svc.get_scan_detail("s1")

        assert result.scan_id == "s1"
        assert result.cluster_id == "c1"
        assert result.scanner_type == "k8s"
        assert result.status == "completed"
        assert result.s3_keys == ["scans/c1/s1/k8s/scan.json"]

    @pytest.mark.asyncio
    async def test_get_detail_not_found_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_scan_detail("nonexistent")

        assert exc_info.value.status_code == 404


class TestScanServiceListClusterScans:

    @pytest.mark.asyncio
    async def test_list_cluster_scans_returns_newest_first(self):
        from datetime import datetime
        svc, repo, _ = make_service()
        repo.list_by_cluster.return_value = [
            MagicMock(
                scan_id="older",
                scanner_type="k8s",
                status="completed",
                created_at=datetime(2024, 1, 15, 10, 0, 0),
                completed_at=datetime(2024, 1, 15, 10, 30, 0),
                s3_keys=["scans/c1/older/k8s/scan.json"],
            ),
            MagicMock(
                scan_id="newer",
                scanner_type="aws",
                status="running",
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
    async def test_list_cluster_scans_returns_empty_list(self):
        svc, repo, _ = make_service()
        repo.list_by_cluster.return_value = []

        result = await svc.list_cluster_scans("c1")

        assert result.total == 0
        assert result.items == []


class TestScanServiceGetRawResultDownloadUrl:

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_returns_presigned_url(self):
        svc, repo, s3 = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            s3_keys=["scans/c1/s1/k8s/scan.json"],
        )

        result = await svc.get_raw_result_download_url("s1")

        assert result.scan_id == "s1"
        assert result.s3_key == "scans/c1/s1/k8s/scan.json"
        assert result.download_url == "https://download-url"
        assert result.expires_in == 600
        s3.generate_presigned_download_url.assert_called_once_with(
            s3_key="scans/c1/s1/k8s/scan.json",
            expires_in=600,
        )

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_not_found_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await svc.get_raw_result_download_url("nonexistent")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_raw_result_download_url_without_files_raises_404(self):
        from fastapi import HTTPException
        svc, repo, _ = make_service()
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
        svc, repo, s3 = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1",
            s3_keys=[
                "scans/c1/s1/k8s/scan.json",
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
        svc, repo, _ = make_service()
        repo.claim_next_queued_scan.return_value = MagicMock(scan_id="s1")

        result = await svc.claim_pending_scan(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            scanner_type="k8s",
            claimed_by="worker-1",
            lease_seconds=300,
        )

        assert result.scan_id == "s1"
        repo.claim_next_queued_scan.assert_called_once()
