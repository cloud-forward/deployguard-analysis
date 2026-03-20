from app.gateway.models import ScanRecord


class TestScanRecordModel:

    def test_model_creation(self):
        """ScanRecord can be instantiated with required fields"""
        record = ScanRecord(
            scan_id="test-scan-001",
            cluster_id="prod-01",
            scanner_type="k8s",
            status="created"
        )
        assert record.scan_id == "test-scan-001"
        assert record.status == "created"
        assert record.s3_keys == [] or record.s3_keys is None  # default empty

    def test_default_status(self):
        """Default status is 'created'"""
        record = ScanRecord(
            scan_id="test-002",
            cluster_id="prod-01",
            scanner_type="aws",
        )
        assert record.status == "created"

    def test_tablename(self):
        """Table name follows convention"""
        assert ScanRecord.__tablename__ == "scan_records"
