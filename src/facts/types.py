"""
Core types and enums for the Fact pipeline.
Defines all allowed fact types and common type aliases.
"""
from enum import Enum
from typing import Literal


class FactType(str, Enum):
    """Allowed fact types according to Fact Schema v2.1"""
    
    # Phase 1: Basic relationships
    POD_USES_SERVICE_ACCOUNT = "pod_uses_service_account"
    SERVICE_ACCOUNT_BOUND_ROLE = "service_account_bound_role"
    SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE = "service_account_bound_cluster_role"
    INGRESS_EXPOSES_SERVICE = "ingress_exposes_service"
    SERVICE_TARGETS_POD = "service_targets_pod"
    POD_MOUNTS_SECRET = "pod_mounts_secret"
    POD_USES_ENV_FROM_SECRET = "pod_uses_env_from_secret"
    USES_IMAGE = "uses_image"
    
    # Phase 2: Permissions
    ROLE_GRANTS_RESOURCE = "role_grants_resource"
    ROLE_GRANTS_POD_EXEC = "role_grants_pod_exec"
    
    # Phase 3: Container escape
    ESCAPES_TO = "escapes_to"
    EXPOSES_TOKEN = "exposes_token"
    
    # Phase 4: Lateral movement
    LATERAL_MOVE = "lateral_move"
    
    # Phase 5: AWS connections
    SERVICE_ACCOUNT_ASSUMES_IAM_ROLE = "service_account_assumes_iam_role"
    IAM_ROLE_ACCESS_RESOURCE = "iam_role_access_resource"
    IAM_USER_ACCESS_RESOURCE = "iam_user_access_resource"
    SECRET_CONTAINS_CREDENTIALS = "secret_contains_credentials"
    SECRET_CONTAINS_AWS_CREDENTIALS = "secret_contains_aws_credentials"
    SECURITY_GROUP_ALLOWS = "security_group_allows"
    INSTANCE_PROFILE_ASSUMES = "instance_profile_assumes"


class NodeType(str, Enum):
    """Allowed node types"""
    
    # K8s resources
    POD = "pod"
    SERVICE_ACCOUNT = "service_account"
    ROLE = "role"
    CLUSTER_ROLE = "cluster_role"
    SECRET = "secret"
    SERVICE = "service"
    INGRESS = "ingress"
    NODE = "node"
    NODE_CREDENTIAL = "node_credential"
    CONTAINER_IMAGE = "container_image"
    
    # AWS resources
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    S3_BUCKET = "s3_bucket"
    RDS = "rds"
    SECURITY_GROUP = "security_group"
    EC2_INSTANCE = "ec2_instance"


# Type aliases for clarity
AccountID = str
Namespace = str
ResourceName = str
Confidence = Literal["high", "medium", "low"]
ValidationLevel = Literal["strict", "normal", "permissive"]