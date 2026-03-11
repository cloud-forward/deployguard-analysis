"""Unit tests for AWS Graph Builder node builders."""
import pytest

from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    EC2InstanceScan,
    RDSInstanceScan,
    S3BucketScan,
    SecurityGroupScan,
)


def make_scan(
    s3_buckets=None,
    rds_instances=None,
    ec2_instances=None,
    security_groups=None,
    iam_roles=None,
) -> AWSScanResult:
    """Return an AWSScanResult populated with the provided test data."""
    return AWSScanResult(
        scan_id="scan-test-001",
        aws_account_id="123456789012",
        scanned_at="2026-03-11T00:00:00Z",
        iam_roles=iam_roles or [],
        s3_buckets=s3_buckets or [],
        rds_instances=rds_instances or [],
        ec2_instances=ec2_instances or [],
        security_groups=security_groups or [],
    )


def build(scan: AWSScanResult):
    """Build graph from scan and return (nodes, edges)."""
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )
    return builder.build(scan, irsa_mappings=[], credential_facts=[])


# ---------------------------------------------------------------------------
# S3 tests
# ---------------------------------------------------------------------------

def test_s3_node_creation():
    # Arrange
    bucket = S3BucketScan(
        name="my-bucket",
        arn="arn:aws:s3:::my-bucket",
        public_access_block={"BlockPublicAcls": True},
        encryption={"Rules": []},
        versioning="Enabled",
        logging_enabled=True,
    )
    scan = make_scan(s3_buckets=[bucket])

    # Act
    nodes, _ = build(scan)

    # Assert
    s3_nodes = [n for n in nodes if n.type == "s3_bucket"]
    assert len(s3_nodes) == 1
    node = s3_nodes[0]
    assert node.id == f"s3:{scan.aws_account_id}:my-bucket"
    assert node.is_crown_jewel is True
    assert node.metadata["scan_id"] == "scan-test-001"


def test_s3_node_public_detection():
    # Arrange
    bucket = S3BucketScan(
        name="public-bucket",
        arn="arn:aws:s3:::public-bucket",
        public_access_block={"BlockPublicAcls": False},
        encryption={"Rules": []},
        versioning="Disabled",
        logging_enabled=False,
    )
    scan = make_scan(s3_buckets=[bucket])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "s3_bucket")
    assert node.metadata["is_public"] is True
    assert "PISM-005" in node.metadata["compliance_violations"]


def test_s3_node_no_encryption():
    # Arrange
    bucket = S3BucketScan(
        name="unencrypted-bucket",
        arn="arn:aws:s3:::unencrypted-bucket",
        public_access_block={"BlockPublicAcls": True},
        encryption=None,
        versioning="Disabled",
        logging_enabled=False,
    )
    scan = make_scan(s3_buckets=[bucket])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "s3_bucket")
    assert node.metadata["has_encryption"] is False
    assert "PISM-029" in node.metadata["compliance_violations"]


# ---------------------------------------------------------------------------
# RDS tests
# ---------------------------------------------------------------------------

def test_rds_node_creation():
    # Arrange
    rds = RDSInstanceScan(
        identifier="my-db",
        arn="arn:aws:rds:us-east-1:123456789012:db:my-db",
        engine="mysql",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=[],
    )
    scan = make_scan(rds_instances=[rds])

    # Act
    nodes, _ = build(scan)

    # Assert
    rds_nodes = [n for n in nodes if n.type == "rds"]
    assert len(rds_nodes) == 1
    node = rds_nodes[0]
    assert node.id == f"rds:{scan.aws_account_id}:my-db"
    assert node.is_crown_jewel is True


def test_rds_node_publicly_accessible():
    # Arrange
    rds = RDSInstanceScan(
        identifier="public-db",
        arn="arn:aws:rds:us-east-1:123456789012:db:public-db",
        engine="postgres",
        storage_encrypted=True,
        publicly_accessible=True,
        vpc_security_groups=[],
    )
    scan = make_scan(rds_instances=[rds])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "rds")
    assert "PISM-007" in node.metadata["compliance_violations"]


# ---------------------------------------------------------------------------
# Security Group tests
# ---------------------------------------------------------------------------

def test_sg_node_public_detection():
    # Arrange
    sg = SecurityGroupScan(
        group_id="sg-abc123",
        group_name="open-sg",
        vpc_id="vpc-001",
        inbound_rules=[
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
        outbound_rules=[],
    )
    scan = make_scan(security_groups=[sg])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "security_group")
    assert node.metadata["is_publicly_accessible"] is True
    assert 22 in node.metadata["open_ports"]


# ---------------------------------------------------------------------------
# EC2 tests
# ---------------------------------------------------------------------------

def test_ec2_node_imdsv1_detection():
    # Arrange
    ec2 = EC2InstanceScan(
        instance_id="i-0abc123",
        instance_type="t3.micro",
        metadata_options={"HttpTokens": "optional"},
        iam_instance_profile=None,
        security_groups=[],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "ec2_instance")
    assert node.metadata["imds_v1_enabled"] is True
    assert "PISM-064" in node.metadata["compliance_violations"]


def test_ec2_node_instance_profile():
    # Arrange
    ec2 = EC2InstanceScan(
        instance_id="i-0def456",
        instance_type="t3.small",
        metadata_options={"HttpTokens": "required"},
        iam_instance_profile={
            "Arn": "arn:aws:iam::123456789012:instance-profile/my-role",
            "Id": "AIPA000000000000EXAMPLE",
        },
        security_groups=[],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    # Act
    nodes, _ = build(scan)

    # Assert
    node = next(n for n in nodes if n.type == "ec2_instance")
    assert node.metadata["has_instance_profile"] is True
    assert node.metadata["instance_profile_role"] == "my-role"
