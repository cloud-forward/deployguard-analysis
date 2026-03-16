from app.models.db_models import ScanRecord


class TestScanRecordModel:

    def test_model_creation(self):
        """ScanRecord can be instantiated with required fields"""
        record = ScanRecord(
            scan_id="test-scan-001",
            cluster_id="prod-01",
            scanner_type="k8s",
            request_source="manual",
            status="queued"
        )
        assert record.scan_id == "test-scan-001"
        assert record.status == "queued"
        assert record.s3_keys == [] or record.s3_keys is None  # default empty

    def test_default_status(self):
        """Default status is 'queued'"""
        record = ScanRecord(
            scan_id="test-002",
            cluster_id="prod-01",
            scanner_type="aws",
            request_source="manual",
        )
        assert record.status == "queued"

    def test_tablename(self):
        """Table name follows convention"""
        assert ScanRecord.__tablename__ == "scan_records"
