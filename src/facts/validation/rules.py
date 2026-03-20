"""
Validation rules for canonical facts.
"""
from typing import Dict, Set, Tuple

from src.facts.types import FactType, NodeType


class ValidationRules:
    """Defines allowed combinations and validation rules"""
    
    # Allowed (subject_type, object_type) combinations for each fact_type
    ALLOWED_COMBINATIONS: Dict[str, Set[Tuple[str, str]]] = {
        FactType.POD_USES_SERVICE_ACCOUNT.value: {
            (NodeType.POD.value, NodeType.SERVICE_ACCOUNT.value),
        },
        FactType.SERVICE_ACCOUNT_BOUND_ROLE.value: {
            (NodeType.SERVICE_ACCOUNT.value, NodeType.ROLE.value),
        },
        FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value: {
            (NodeType.SERVICE_ACCOUNT.value, NodeType.CLUSTER_ROLE.value),
        },
        FactType.INGRESS_EXPOSES_SERVICE.value: {
            (NodeType.INGRESS.value, NodeType.SERVICE.value),
        },
        FactType.SERVICE_TARGETS_POD.value: {
            (NodeType.SERVICE.value, NodeType.POD.value),
        },
        FactType.POD_MOUNTS_SECRET.value: {
            (NodeType.POD.value, NodeType.SECRET.value),
        },
        FactType.POD_USES_ENV_FROM_SECRET.value: {
            (NodeType.POD.value, NodeType.SECRET.value),
        },
        FactType.USES_IMAGE.value: {
            (NodeType.POD.value, NodeType.CONTAINER_IMAGE.value),
        },
        FactType.ROLE_GRANTS_RESOURCE.value: {
            (NodeType.ROLE.value, NodeType.SECRET.value),
            (NodeType.ROLE.value, NodeType.POD.value),
            (NodeType.CLUSTER_ROLE.value, NodeType.SECRET.value),
            (NodeType.CLUSTER_ROLE.value, NodeType.POD.value),
        },
        FactType.ROLE_GRANTS_POD_EXEC.value: {
            (NodeType.ROLE.value, NodeType.POD.value),
            (NodeType.CLUSTER_ROLE.value, NodeType.POD.value),
        },
        FactType.ESCAPES_TO.value: {
            (NodeType.POD.value, NodeType.NODE.value),
        },
        FactType.EXPOSES_TOKEN.value: {
            (NodeType.NODE.value, NodeType.SERVICE_ACCOUNT.value),
        },
        FactType.LATERAL_MOVE.value: {
            (NodeType.POD.value, NodeType.SERVICE.value),
        },
        FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value: {
            (NodeType.SERVICE_ACCOUNT.value, NodeType.IAM_ROLE.value),
        },
        FactType.IAM_ROLE_ACCESS_RESOURCE.value: {
            (NodeType.IAM_ROLE.value, NodeType.S3_BUCKET.value),
            (NodeType.IAM_ROLE.value, NodeType.RDS.value),
        },
        FactType.IAM_USER_ACCESS_RESOURCE.value: {
            (NodeType.IAM_USER.value, NodeType.S3_BUCKET.value),
            (NodeType.IAM_USER.value, NodeType.RDS.value),
        },
        FactType.SECRET_CONTAINS_CREDENTIALS.value: {
            (NodeType.SECRET.value, NodeType.RDS.value),
            (NodeType.SECRET.value, NodeType.S3_BUCKET.value),
        },
        FactType.SECRET_CONTAINS_AWS_CREDENTIALS.value: {
            (NodeType.SECRET.value, NodeType.IAM_USER.value),
        },
        FactType.SECURITY_GROUP_ALLOWS.value: {
            (NodeType.SECURITY_GROUP.value, NodeType.RDS.value),
            (NodeType.SECURITY_GROUP.value, NodeType.EC2_INSTANCE.value),
        },
        FactType.INSTANCE_PROFILE_ASSUMES.value: {
            (NodeType.EC2_INSTANCE.value, NodeType.IAM_ROLE.value),
        },
    }
    
    # Node type to ID prefix mapping
    TYPE_PREFIX_MAP: Dict[str, str] = {
        NodeType.POD.value: "pod:",
        NodeType.SERVICE_ACCOUNT.value: "sa:",
        NodeType.ROLE.value: "role:",
        NodeType.CLUSTER_ROLE.value: "cluster_role:",
        NodeType.SECRET.value: "secret:",
        NodeType.SERVICE.value: "service:",
        NodeType.INGRESS.value: "ingress:",
        NodeType.NODE.value: "node:",
        NodeType.NODE_CREDENTIAL.value: "node_cred:",
        NodeType.CONTAINER_IMAGE.value: "container_image:",
        NodeType.IAM_ROLE.value: "iam:",
        NodeType.IAM_USER.value: "iam_user:",
        NodeType.S3_BUCKET.value: "s3:",
        NodeType.RDS.value: "rds:",
        NodeType.SECURITY_GROUP.value: "sg:",
        NodeType.EC2_INSTANCE.value: "ec2:",
    }
    
    # Allowed confidence values
    ALLOWED_CONFIDENCE = {"high", "medium", "low"}