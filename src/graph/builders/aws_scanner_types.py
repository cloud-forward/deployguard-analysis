"""Data classes representing AWS Scanner output consumed by AWS Graph Builder."""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class IAMRoleScan:
    """Represents a scanned IAM Role."""

    name: str
    arn: str
    is_irsa: bool
    irsa_oidc_issuer: Optional[str]
    attached_policies: list[dict[str, Any]]
    inline_policies: list[dict[str, Any]]
    trust_policy: dict[str, Any]


@dataclass
class S3BucketScan:
    """Represents a scanned S3 Bucket."""

    name: str
    arn: str
    public_access_block: Optional[dict[str, Any]]
    encryption: Optional[dict[str, Any]]
    versioning: str
    logging_enabled: bool


@dataclass
class RDSInstanceScan:
    """Represents a scanned RDS Instance."""

    identifier: str
    arn: str
    engine: str
    storage_encrypted: bool
    publicly_accessible: bool
    vpc_security_groups: list[str]


@dataclass
class EC2InstanceScan:
    """Represents a scanned EC2 Instance."""

    instance_id: str
    instance_type: str
    metadata_options: dict[str, Any]
    iam_instance_profile: Optional[dict[str, Any]]
    security_groups: list[str]
    tags: dict[str, Any]


@dataclass
class SecurityGroupScan:
    """Represents a scanned Security Group."""

    group_id: str
    group_name: str
    vpc_id: str
    inbound_rules: list[dict[str, Any]]
    outbound_rules: list[dict[str, Any]]


@dataclass
class AccessKeyScan:
    """Represents a scanned IAM Access Key."""

    access_key_id: str
    status: str        # "Active" | "Inactive"
    create_date: str   # ISO 8601


@dataclass
class IAMUserScan:
    """Represents a scanned IAM User."""

    username: str
    arn: str
    access_keys: list[AccessKeyScan]
    attached_policies: list[dict[str, Any]]
    inline_policies: list[dict[str, Any]]
    has_mfa: bool
    last_used: Optional[str]        # ISO 8601 or None


@dataclass
class AWSScanResult:
    """Represents the full result of an AWS environment scan."""

    scan_id: str
    aws_account_id: str
    scanned_at: str
    iam_roles: list[IAMRoleScan]
    s3_buckets: list[S3BucketScan]
    rds_instances: list[RDSInstanceScan]
    ec2_instances: list[EC2InstanceScan]
    security_groups: list[SecurityGroupScan]
    iam_users: list[IAMUserScan] = field(default_factory=list)
