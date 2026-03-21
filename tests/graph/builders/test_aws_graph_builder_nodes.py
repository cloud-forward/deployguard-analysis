"""Unit tests for AWS Graph Builder node builders."""
import pytest

from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.build_result_types import AWSBuildResult, unpack_build_result
from src.graph.builders.aws_scanner_types import (
    AccessKeyScan,
    AWSScanResult,
    EC2InstanceScan,
    IAMRoleScan,
    IAMUserScan,
    RDSInstanceScan,
    S3BucketScan,
    SecurityGroupScan,
)
from src.graph.builders.iam_policy_types import IAMPolicyAnalysisResult, IAMUserPolicyAnalysisResult, TrustPolicyAnalysis


def make_scan(
    s3_buckets=None,
    rds_instances=None,
    ec2_instances=None,
    security_groups=None,
    iam_roles=None,
    iam_users=None,
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
        iam_users=iam_users or [],
    )


def build(scan: AWSScanResult, policy_results=None, user_policy_results=None):
    """Build graph from scan and return (nodes, edges)."""
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )
    result = builder.build(
        scan,
        irsa_mappings=[],
        credential_facts=[],
        policy_results=policy_results,
        user_policy_results=user_policy_results,
    )
    return result.nodes, result.edges


def test_build_returns_aws_build_result():
    scan = make_scan()
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )

    result = builder.build(scan, irsa_mappings=[], credential_facts=[])

    assert isinstance(result, AWSBuildResult)
    assert result.nodes == []
    assert result.edges == []
    assert result.metadata == {
        "graph_id": f"{scan.scan_id}-graph",
        "scan_id": scan.scan_id,
        "account_id": scan.aws_account_id,
    }


def test_transitional_unpack_adapter_works_with_aws_build_result():
    bucket = S3BucketScan(
        name="my-bucket",
        arn="arn:aws:s3:::my-bucket",
        public_access_block={"BlockPublicAcls": True},
        encryption={"Rules": []},
        versioning="Enabled",
        logging_enabled=True,
    )
    scan = make_scan(s3_buckets=[bucket])
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )

    result = builder.build(scan, irsa_mappings=[], credential_facts=[])
    nodes, edges = unpack_build_result(result)

    assert nodes == result.nodes
    assert edges == result.edges
    assert [node.id for node in nodes] == [f"s3:{scan.aws_account_id}:my-bucket"]


def make_iam_role(name="AdminRole") -> IAMRoleScan:
    """Return a minimal IAMRoleScan for testing."""
    return IAMRoleScan(
        name=name,
        arn=f"arn:aws:iam::123456789012:role/{name}",
        is_irsa=False,
        irsa_oidc_issuer=None,
        attached_policies=[],
        inline_policies=[],
        trust_policy={},
    )


def make_trust_analysis(**kwargs) -> TrustPolicyAnalysis:
    """Return a TrustPolicyAnalysis with sensible defaults, overridable via kwargs."""
    defaults = dict(
        is_irsa_enabled=False,
        oidc_issuer=None,
        allows_all_sa=False,
        allowed_sa_patterns=[],
        allowed_sa_explicit=[],
        allows_ec2=False,
        allows_lambda=False,
        cross_account_principals=[],
    )
    defaults.update(kwargs)
    return TrustPolicyAnalysis(**defaults)


def make_iam_user(username="web-app-deployer", active_keys=1, has_mfa=False) -> IAMUserScan:
    """Return a minimal IAMUserScan for testing."""
    keys = [
        AccessKeyScan(
            access_key_id=f"AKIA000000000000{i:04d}",
            status="Active",
            create_date="2026-01-01T00:00:00Z",
        )
        for i in range(active_keys)
    ]
    return IAMUserScan(
        username=username,
        arn=f"arn:aws:iam::123456789012:user/{username}",
        access_keys=keys,
        attached_policies=[],
        inline_policies=[],
        has_mfa=has_mfa,
        last_used=None,
    )


def make_iam_user_policy_analysis(username="web-app-deployer", tier=1, **kwargs) -> IAMUserPolicyAnalysisResult:
    """Return an IAMUserPolicyAnalysisResult with sensible defaults."""
    defaults = dict(
        username=username,
        user_arn=f"arn:aws:iam::123456789012:user/{username}",
        account_id="123456789012",
        tier=tier,
        tier_reason=f"tier_{tier}_reason",
        resource_access=[],
        has_privilege_escalation=False,
        has_data_exfiltration_risk=False,
        has_credential_access=False,
    )
    defaults.update(kwargs)
    return IAMUserPolicyAnalysisResult(**defaults)


def make_policy_analysis(role_name="AdminRole", tier=1, **kwargs) -> IAMPolicyAnalysisResult:
    """Return an IAMPolicyAnalysisResult with sensible defaults."""
    defaults = dict(
        role_name=role_name,
        role_arn=f"arn:aws:iam::123456789012:role/{role_name}",
        account_id="123456789012",
        tier=tier,
        tier_reason=f"tier_{tier}_reason",
        trust_analysis=make_trust_analysis(),
        resource_access=[],
        has_privilege_escalation=False,
        has_data_exfiltration_risk=False,
        has_credential_access=False,
    )
    defaults.update(kwargs)
    return IAMPolicyAnalysisResult(**defaults)


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


# ---------------------------------------------------------------------------
# IAM Role tests
# ---------------------------------------------------------------------------

def test_iam_role_tier1_is_crown_jewel():
    role = make_iam_role("AdminRole")
    analysis = make_policy_analysis(role_name="AdminRole", tier=1)
    scan = make_scan(iam_roles=[role])

    nodes, _ = build(scan, policy_results=[analysis])

    node = next(n for n in nodes if n.type == "iam_role")
    assert node.is_crown_jewel is True
    assert node.metadata["tier"] == 1
    assert node.metadata["tier_reason"] is not None


def test_iam_role_tier2_is_crown_jewel():
    role = make_iam_role("PowerUserRole")
    analysis = make_policy_analysis(role_name="PowerUserRole", tier=2)
    scan = make_scan(iam_roles=[role])

    nodes, _ = build(scan, policy_results=[analysis])

    node = next(n for n in nodes if n.type == "iam_role")
    assert node.is_crown_jewel is True


def test_iam_role_tier3_not_crown_jewel():
    role = make_iam_role("ReadOnlyRole")
    analysis = make_policy_analysis(role_name="ReadOnlyRole", tier=3)
    scan = make_scan(iam_roles=[role])

    nodes, _ = build(scan, policy_results=[analysis])

    node = next(n for n in nodes if n.type == "iam_role")
    assert node.is_crown_jewel is False


def test_iam_role_no_policy_analysis():
    role = make_iam_role("SomeRole")
    scan = make_scan(iam_roles=[role])

    nodes, _ = build(scan)  # no policy_results

    node = next(n for n in nodes if n.type == "iam_role")
    assert node.is_crown_jewel is False
    assert node.metadata["tier"] is None
    assert node.metadata["tier_reason"] == "policy_analysis_unavailable"


def test_iam_role_trust_metadata():
    role = make_iam_role("IrsaRole")
    trust = make_trust_analysis(is_irsa_enabled=True, allows_all_sa=True)
    analysis = make_policy_analysis(role_name="IrsaRole", tier=2, trust_analysis=trust)
    scan = make_scan(iam_roles=[role])

    nodes, _ = build(scan, policy_results=[analysis])

    node = next(n for n in nodes if n.type == "iam_role")
    assert node.metadata["trust"]["is_irsa_enabled"] is True
    assert node.metadata["trust"]["allows_all_sa"] is True


# ---------------------------------------------------------------------------
# IAM User tests
# ---------------------------------------------------------------------------

def test_iam_user_node_creation():
    # Arrange: 1 active key, no MFA
    user = make_iam_user(username="web-app-deployer", active_keys=1, has_mfa=False)
    scan = make_scan(iam_users=[user])
    # Act
    nodes, _ = build(scan)
    # Assert
    node = next(n for n in nodes if n.type == "iam_user")
    assert node.id == "iam_user:123456789012:web-app-deployer"
    assert node.type == "iam_user"
    assert node.metadata["has_active_key"] is True
    assert "PISM-IAM-001" in node.metadata["compliance_violations"]


def test_iam_user_multiple_active_keys():
    # Arrange: 2 active keys
    user = make_iam_user(username="web-app-deployer", active_keys=2, has_mfa=False)
    scan = make_scan(iam_users=[user])
    # Act
    nodes, _ = build(scan)
    # Assert
    node = next(n for n in nodes if n.type == "iam_user")
    assert "PISM-IAM-002" in node.metadata["compliance_violations"]


def test_iam_user_tier1_crown_jewel():
    # Arrange: tier=1 policy analysis
    user = make_iam_user(username="web-app-deployer")
    analysis = make_iam_user_policy_analysis(username="web-app-deployer", tier=1)
    scan = make_scan(iam_users=[user])
    # Act
    nodes, _ = build(scan, user_policy_results=[analysis])
    # Assert
    node = next(n for n in nodes if n.type == "iam_user")
    assert node.is_crown_jewel is True


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
