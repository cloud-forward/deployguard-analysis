"""
Node ID generation utilities.
Ensures consistent ID format across all extractors.
"""
from typing import Optional


class NodeIDGenerator:
    """Generate consistent node IDs according to schema rules"""
    
    @staticmethod
    def pod(namespace: str, name: str) -> str:
        return f"pod:{namespace}:{name}"
    
    @staticmethod
    def service_account(namespace: str, name: str) -> str:
        return f"sa:{namespace}:{name}"
    
    @staticmethod
    def role(namespace: str, name: str) -> str:
        return f"role:{namespace}:{name}"
    
    @staticmethod
    def cluster_role(name: str) -> str:
        return f"cluster_role:{name}"
    
    @staticmethod
    def secret(namespace: str, name: str) -> str:
        return f"secret:{namespace}:{name}"
    
    @staticmethod
    def service(namespace: str, name: str) -> str:
        return f"service:{namespace}:{name}"
    
    @staticmethod
    def ingress(namespace: str, name: str) -> str:
        return f"ingress:{namespace}:{name}"
    
    @staticmethod
    def node(node_name: str) -> str:
        return f"node:{node_name}"

    @staticmethod
    def node_credential(node_name: str, credential_type: str) -> str:
        return f"node_cred:{node_name}:{credential_type}"

    @staticmethod
    def container_image(image_ref: str) -> str:
        return f"container_image:{image_ref}"
    
    @staticmethod
    def iam_role(account_id: str, role_name: str) -> str:
        return f"iam:{account_id}:{role_name}"
    
    @staticmethod
    def iam_user(account_id: str, username: str) -> str:
        return f"iam_user:{account_id}:{username}"
    
    @staticmethod
    def s3_bucket(account_id: str, bucket_name: str) -> str:
        return f"s3:{account_id}:{bucket_name}"
    
    @staticmethod
    def rds(account_id: str, db_identifier: str) -> str:
        return f"rds:{account_id}:{db_identifier}"
    
    @staticmethod
    def security_group(account_id: str, group_id: str) -> str:
        return f"sg:{account_id}:{group_id}"
    
    @staticmethod
    def ec2_instance(account_id: str, instance_id: str) -> str:
        return f"ec2:{account_id}:{instance_id}"
    
    @staticmethod
    def parse_node_type(node_id: str) -> Optional[str]:
        """Extract node type from node ID"""
        if not node_id or ":" not in node_id:
            return None
        
        prefix = node_id.split(":", 1)[0]
        
        # Handle special cases
        if prefix == "sa":
            return "service_account"
        elif prefix == "node_cred":
            return "node_credential"
        elif prefix == "container_image":
            return "container_image"
        
        return prefix
