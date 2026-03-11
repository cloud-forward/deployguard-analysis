"""Unit tests for AWS Graph Builder edge builders."""
import pytest
from datetime import datetime

from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    EC2InstanceScan,
    RDSInstanceScan,
    SecurityGroupScan,
)
from src.graph.builders.cross_domain_types import IRSAMapping, SecretContainsCredentialsFact


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
        aws_account_id="account",
        scanned_at="2026-03-11T00:00:00Z",
        iam_roles=iam_roles or [],
        s3_buckets=s3_buckets or [],
        rds_instances=rds_instances or [],
        ec2_instances=ec2_instances or [],
        security_groups=security_groups or [],
    )


def build(scan: AWSScanResult, irsa_mappings=None, credential_facts=None):
    """Build graph from scan and return (nodes, edges)."""
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )
    return builder.build(
        scan,
        irsa_mappings=irsa_mappings or [],
        credential_facts=credential_facts or [],
    )


# ---------------------------------------------------------------------------
# SG allows RDS
# ---------------------------------------------------------------------------

def test_sg_allows_rds_edge():
    rds = RDSInstanceScan(
        identifier="db-id",
        arn="arn:aws:rds:us-east-1:account:db:db-id",
        engine="mysql",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=["sg-id"],
    )
    scan = make_scan(rds_instances=[rds])

    _, edges = build(scan)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "security_group_allows"
    assert edge.source == "sg:account:sg-id"
    assert edge.target == "rds:account:db-id"
    assert edge.metadata["resource_type"] == "rds"


# ---------------------------------------------------------------------------
# SG allows EC2
# ---------------------------------------------------------------------------

def test_sg_allows_ec2_edge():
    ec2 = EC2InstanceScan(
        instance_id="instance-id",
        instance_type="t3.micro",
        metadata_options={"HttpTokens": "required"},
        iam_instance_profile=None,
        security_groups=["sg-1", "sg-2"],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    _, edges = build(scan)

    sg_edges = [e for e in edges if e.type == "security_group_allows"]
    assert len(sg_edges) == 2
    assert all(e.type == "security_group_allows" for e in sg_edges)


# ---------------------------------------------------------------------------
# Instance profile edge
# ---------------------------------------------------------------------------

def test_instance_profile_edge():
    ec2 = EC2InstanceScan(
        instance_id="instance-id",
        instance_type="t3.micro",
        metadata_options={"HttpTokens": "required"},
        iam_instance_profile={"Arn": "arn:aws:iam::account:instance-profile/role-name"},
        security_groups=[],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    _, edges = build(scan)

    profile_edges = [e for e in edges if e.type == "instance_profile_assumes"]
    assert len(profile_edges) == 1
    edge = profile_edges[0]
    assert edge.type == "instance_profile_assumes"
    assert edge.source == "ec2:account:instance-id"
    assert edge.target == "iam:account:role-name"
    assert edge.metadata["via"] == "instance_profile"


# ---------------------------------------------------------------------------
# IRSA edge
# ---------------------------------------------------------------------------

def test_irsa_edge():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="name",
        iam_role_arn="arn:aws:iam::account:role/role",
        iam_role_name="role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "service_account_assumes_iam_role"
    assert edge.source == "sa:namespace:name"
    assert edge.target == "iam:account:role"
    assert edge.metadata["via"] == "irsa"


# ---------------------------------------------------------------------------
# Credential edge
# ---------------------------------------------------------------------------

def test_credential_edge():
    fact = SecretContainsCredentialsFact(
        secret_namespace="namespace",
        secret_name="name",
        target_type="rds",
        target_id="db-id",
        matched_keys=["DB_PASSWORD", "DB_USER"],
        confidence="high",
    )
    scan = make_scan()

    _, edges = build(scan, credential_facts=[fact])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "secret_contains_credentials"
    assert edge.source == "secret:namespace:name"
    assert edge.target == "rds:account:db-id"
    assert "matched_keys" in edge.metadata


# ---------------------------------------------------------------------------
# Dangling edge allowed
# ---------------------------------------------------------------------------

def test_dangling_edge_allowed():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="nonexistent-sa",
        iam_role_arn="arn:aws:iam::account:role/some-role",
        iam_role_name="some-role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    assert len(edges) == 1
    assert edges[0].source == "sa:namespace:nonexistent-sa"


# ---------------------------------------------------------------------------
# Edge metadata completeness
# ---------------------------------------------------------------------------

def test_edge_metadata_completeness():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="name",
        iam_role_arn="arn:aws:iam::account:role/role",
        iam_role_name="role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    edge = edges[0]
    assert "scan_id" in edge.metadata
    assert "source_type" in edge.metadata
    assert "created_at" in edge.metadata

    created_at = edge.metadata["created_at"]
    # Validate ISO 8601 format by parsing it (strip trailing Z for fromisoformat)
    datetime.fromisoformat(created_at.rstrip("Z"))
