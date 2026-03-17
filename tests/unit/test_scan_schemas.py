"""
Tests for the scan Pydantic models.
"""
import pytest
from pydantic import ValidationError
from app.models.schemas import (
    ScanStartRequest,
    ScannerType,
    UploadUrlRequest,
    ScanCompleteRequest,
    ScanStatusResponse,
)


class TestScanStartRequest:

    def test_valid_request(self):
        """Valid request with all fields"""
        from uuid import UUID
        req = ScanStartRequest(cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="k8s")
        assert req.cluster_id == UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert req.scanner_type == ScannerType.k8s
        assert req.request_source == "manual"

    def test_valid_scanner_types(self):
        """All 4 scanner types are accepted"""
        for st, expected in [("k8s", ScannerType.k8s), ("aws", ScannerType.aws), ("image", ScannerType.image), ("runtime", ScannerType.runtime)]:
            req = ScanStartRequest(cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type=st)
            assert req.scanner_type == expected

    def test_invalid_scanner_type(self):
        """Invalid scanner_type raises ValidationError"""
        with pytest.raises(ValidationError):
            ScanStartRequest(cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890", scanner_type="invalid")

    def test_missing_cluster_id(self):
        """Missing cluster_id raises ValidationError"""
        with pytest.raises(ValidationError):
            ScanStartRequest(scanner_type="k8s")

    def test_invalid_cluster_id_format_rejected(self):
        """Non-UUID cluster_id raises ValidationError"""
        with pytest.raises(ValidationError):
            ScanStartRequest(cluster_id="not-a-uuid", scanner_type="k8s")

    def test_valid_request_sources(self):
        for request_source in ("manual", "scheduled"):
            req = ScanStartRequest(
                cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                scanner_type="k8s",
                request_source=request_source,
            )
            assert req.request_source == request_source

    def test_invalid_request_source(self):
        with pytest.raises(ValidationError):
            ScanStartRequest(
                cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                scanner_type="k8s",
                request_source="api",
            )


class TestUploadUrlRequest:

    def test_valid_json_file(self):
        req = UploadUrlRequest(file_name="k8s_scan.json")
        assert req.file_name == "k8s_scan.json"

    def test_non_json_file_rejected(self):
        """Only .json files allowed"""
        with pytest.raises(ValidationError):
            UploadUrlRequest(file_name="scan.txt")

    def test_empty_file_name(self):
        with pytest.raises(ValidationError):
            UploadUrlRequest(file_name="")


class TestScanCompleteRequest:

    def test_valid_files_list(self):
        req = ScanCompleteRequest(files=["scans/c1/s1/k8s.json"])
        assert len(req.files) == 1

    def test_empty_files_rejected(self):
        """Empty files list not allowed"""
        with pytest.raises(ValidationError):
            ScanCompleteRequest(files=[])


class TestScanStatusResponse:

    def test_serialization(self):
        """Response model serializes to expected JSON structure"""
        from datetime import datetime
        resp = ScanStatusResponse(
            scan_id="abc-123",
            cluster_id="prod-01",
            scanner_type="k8s",
            status="processing",
            created_at=datetime(2024, 1, 15, 10, 0, 0),
            completed_at=None,
            files=["scans/prod-01/abc-123/k8s.json"]
        )
        data = resp.model_dump()
        assert data["status"] == "processing"
        assert data["completed_at"] is None
        assert len(data["files"]) == 1
