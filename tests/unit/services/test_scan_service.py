import re
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.application.services.scan_service import ScanService


def make_service():
    mock_repo = AsyncMock()
    mock_s3 = MagicMock()
    mock_s3.generate_presigned_upload_url.return_value = (
        "https://presigned-url", "scans/c1/s1/k8s/f.json"
    )
    mock_s3.verify_file_exists.return_value = True
    svc = ScanService(scan_repository=mock_repo, s3_service=mock_s3)
    return svc, mock_repo, mock_s3


class TestScanServiceStartScan:

    @pytest.mark.asyncio
    async def test_start_scan_returns_scan_id(self):
        """start_scan returns a scan_id and status=queued"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", scanner_type="k8s", request_source="test")

        assert result.scan_id is not None
        assert result.status == "queued"

    @pytest.mark.asyncio
    async def test_scan_id_format(self):
        """scan_id format must be {YYYYMMDDTHHmmSS}-{scanner_type}"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        result = await svc.start_scan(cluster_id="prod-01", scanner_type="k8s", request_source="test")

        assert re.match(r"^\d{8}T\d{6}-k8s$", result.scan_id), (
            f"scan_id '{result.scan_id}' does not match expected format"
        )

    @pytest.mark.asyncio
    async def test_start_scan_creates_db_record(self):
        """start_scan calls repository.create exactly once"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None

        await svc.start_scan("prod-01", "k8s", "test")

        repo.create.assert_called_once()
        _, kwargs = repo.create.call_args
        assert kwargs["status"] == "queued"
        assert kwargs["request_source"] == "test"
        assert kwargs["scanner_type"] == "k8s"

    @pytest.mark.asyncio
    async def test_start_scan_duplicate_raises_409(self):
        """start_scan raises 409 if an active scan already exists"""
        from fastapi import HTTPException
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = MagicMock(status="queued")

        with pytest.raises(HTTPException) as exc_info:
            await svc.start_scan("prod-01", "k8s", "test")

        assert exc_info.value.status_code == 409
        assert "already running" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_allow_new_scan_if_previous_completed(self):
        """start_scan succeeds when find_active_scan returns None (prior scan completed)"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None  # completed scans are not active

        result = await svc.start_scan("prod-01", "k8s", "test")

        assert result.status == "queued"
        repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_allow_new_scan_if_previous_failed(self):
        """start_scan succeeds when find_active_scan returns None (prior scan failed)"""
        svc, repo, _ = make_service()
        repo.find_active_scan.return_value = None  # failed scans are not active

        result = await svc.start_scan("prod-01", "aws", "test")

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
    async def test_complete_scan_returns_processing(self):
        """complete_scan returns status=processing on success"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        result = await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        assert result.status == "processing"
        assert result.scan_id == "s1"

    @pytest.mark.asyncio
    async def test_complete_scan_calls_update(self):
        """complete_scan calls repository.update with status=processing"""
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(scan_id="s1", status="uploading")

        await svc.complete_scan("s1", ["scans/c1/s1/k8s/f.json"])

        repo.update.assert_called_once()
        call_kwargs = repo.update.call_args
        assert call_kwargs[1]["status"] == "processing"

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


class TestScanServiceGetStatus:

    @pytest.mark.asyncio
    async def test_get_status_returns_current_state(self):
        """get_scan_status returns current status and scan metadata"""
        from datetime import datetime
        svc, repo, _ = make_service()
        repo.get_by_scan_id.return_value = MagicMock(
            scan_id="s1", cluster_id="c1", scanner_type="k8s",
            status="processing",
            created_at=datetime(2024, 1, 15), completed_at=None,
            s3_keys=["scans/c1/s1/k8s.json"]
        )

        result = await svc.get_scan_status("s1")

        assert result.status == "processing"
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
