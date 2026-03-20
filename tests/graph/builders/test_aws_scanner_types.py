from src.graph.builders.aws_scanner_types import AWSScanResult, RDSInstanceScan


def test_aws_scan_result_accepts_region():
    scan = AWSScanResult(
        scan_id="scan-1",
        aws_account_id="123456789012",
        scanned_at="2026-03-20T00:00:00Z",
        iam_roles=[],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
        region="us-east-1",
    )

    assert scan.region == "us-east-1"


def test_rds_instance_scan_accepts_engine_version():
    instance = RDSInstanceScan(
        identifier="production-db",
        arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
        engine="postgres",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=[],
        engine_version="16.3",
    )

    assert instance.engine_version == "16.3"
