"""Cross-domain data classes for IRSA mappings and secret credential facts."""

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class IRSAMapping:
    """Represents an IRSA (IAM Roles for Service Accounts) mapping.

    Attributes:
        sa_namespace: The Kubernetes namespace of the service account.
        sa_name: The name of the Kubernetes service account.
        iam_role_arn: The full ARN of the IAM role being assumed.
        iam_role_name: The name of the IAM role being assumed.
        account_id: The AWS account ID that owns the IAM role.
    """

    sa_namespace: str
    sa_name: str
    iam_role_arn: str
    iam_role_name: str
    account_id: str


@dataclass
class SecretContainsCredentialsFact:
    """Represents a fact that a Kubernetes secret contains credentials for an AWS resource.

    Attributes:
        secret_namespace: The Kubernetes namespace of the secret.
        secret_name: The name of the Kubernetes secret.
        target_type: The type of AWS resource the credentials belong to (e.g., "rds", "s3", "iam_user").
        For iam_user targets, the graph emits a distinct secret_contains_aws_credentials edge.
        target_id: The identifier of the target AWS resource.
        matched_keys: List of secret keys that matched credential patterns.
        confidence: Confidence level of the credential match (e.g., "high", "medium", "low").
    """

    secret_namespace: str
    secret_name: str
    target_type: Literal["rds", "s3", "iam_user"]
    target_id: str
    matched_keys: list[str] = field(default_factory=list)
    confidence: str = "medium"


@dataclass
class IRSABridgeResult:
    """Unified bridge output consumed by AWSGraphBuilder."""

    irsa_mappings: list[IRSAMapping] = field(default_factory=list)
    credential_facts: list[SecretContainsCredentialsFact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped_irsa: int = 0
    skipped_credentials: int = 0
