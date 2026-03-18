"""Data classes representing IAM Policy analysis results."""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class TrustPolicyAnalysis:
    """Represents the analysis of an IAM Role trust policy."""

    is_irsa_enabled: bool
    oidc_issuer: Optional[str]
    allows_all_sa: bool
    allowed_sa_patterns: list[str]   # e.g. ["system:serviceaccount:production:*"]
    allowed_sa_explicit: list[str]   # e.g. ["system:serviceaccount:production:api-sa"]
    allows_ec2: bool
    allows_lambda: bool
    cross_account_principals: list[str]


@dataclass
class ResourceAccess:
    """Represents access to a specific AWS resource/service from a policy statement."""

    service: str                     # lowercase: "s3", "rds", "iam", "ec2"
    actions: list[str]
    resource_arns: list[str]
    effect: str                      # "Allow" | "Deny"
    is_wildcard_action: bool
    is_wildcard_resource: bool
    policy_name: Optional[str]
    policy_arn: Optional[str]
    conditions: Optional[dict[str, Any]]


@dataclass
class IAMUserPolicyAnalysisResult:
    """Represents the full IAM policy analysis result for a user."""

    username: str
    user_arn: str
    account_id: str
    tier: Optional[int]              # 1 | 2 | 3 | None
    tier_reason: str
    resource_access: list[ResourceAccess]
    has_privilege_escalation: bool
    has_data_exfiltration_risk: bool
    has_credential_access: bool


@dataclass
class IAMPolicyAnalysisResult:
    """Represents the full IAM policy analysis result for a role."""

    role_name: str
    role_arn: str
    account_id: str
    tier: Optional[int]              # 1 | 2 | 3 | None
    tier_reason: str
    trust_analysis: TrustPolicyAnalysis
    resource_access: list[ResourceAccess]
    has_privilege_escalation: bool
    has_data_exfiltration_risk: bool
    has_credential_access: bool
