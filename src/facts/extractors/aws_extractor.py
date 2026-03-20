"""
AWS Fact Extractor.
Wraps existing AWS graph builders to generate canonical facts (Phase 5).
"""
from typing import Any, Dict, List

from src.facts.extractors.base_extractor import BaseExtractor
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.facts.id_generator import NodeIDGenerator

# Import existing AWS builders
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder
from src.graph.builders.iam_policy_parser import parse_all_roles, parse_all_users
from src.graph.builders.aws_scanner_types import AWSScanResult


class AWSFactExtractor(BaseExtractor):
    """Extract AWS facts by wrapping existing builders"""
    
    def __init__(self):
        super().__init__("aws")
        self.id_gen = NodeIDGenerator()
        self.bridge_builder = IRSABridgeBuilder()
    
    def extract(self, scan_data: Dict[str, Any], **kwargs) -> List[Fact]:
        """
        Extract AWS facts (Phase 5: cross-domain).
        
        Args:
            scan_data: AWS scanner output
            **kwargs: Must include 'k8s_scan' for cross-domain facts
        
        Returns:
            List of Facts
        """
        scan_id = scan_data.get("scan_id", "unknown")
        self._log_extraction_start(scan_id)
        
        facts: List[Fact] = []
        
        try:
            # Parse AWS scan result
            aws_scan = self._parse_aws_scan(scan_data)
            k8s_scan = kwargs.get("k8s_scan")
            
            if not k8s_scan:
                self.logger.warning(
                    "K8s scan not provided, skipping cross-domain facts",
                    scan_id=scan_id,
                )
                return facts
            
            # Extract cross-domain facts using existing bridge builder
            facts.extend(self._extract_cross_domain_facts(k8s_scan, aws_scan))
            
            # Extract IAM policy facts
            facts.extend(self._extract_iam_role_access_facts(aws_scan))
            facts.extend(self._extract_iam_user_access_facts(aws_scan))
            
            # Extract infrastructure facts
            facts.extend(self._extract_security_group_facts(aws_scan))
            facts.extend(self._extract_instance_profile_facts(aws_scan))
            
            self._log_extraction_complete(scan_id, len(facts))
            
        except Exception as e:
            self._log_error(scan_id, e, {"phase": "aws_extraction"})
            raise
        
        return facts
    
    def _parse_aws_scan(self, scan_data: Dict[str, Any]) -> Any:
        """Parse raw scan data into AWSScanResult"""
        # This is a simplified version - actual implementation should use proper dataclass parsing
        return scan_data
    
    def _extract_cross_domain_facts(
        self, k8s_scan: Dict[str, Any], aws_scan: Any
    ) -> List[Fact]:
        """Extract cross-domain facts using existing IRSABridgeBuilder"""
        facts: List[Fact] = []
        
        # Use existing bridge builder
        bridge_result = self.bridge_builder.build(k8s_scan, aws_scan)
        
        # Convert IRSA mappings to facts
        for mapping in bridge_result.irsa_mappings:
            facts.append(Fact(
                fact_type=FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
                subject_id=self.id_gen.service_account(
                    mapping.sa_namespace, mapping.sa_name
                ),
                subject_type=NodeType.SERVICE_ACCOUNT.value,
                object_id=self.id_gen.iam_role(mapping.account_id, mapping.iam_role_name),
                object_type=NodeType.IAM_ROLE.value,
                metadata={
                    "annotation": "eks.amazonaws.com/role-arn",
                    "role_arn": mapping.iam_role_arn,
                    "via": "irsa",
                },
            ))
        
        # Convert credential facts
        for cred_fact in bridge_result.credential_facts:
            if cred_fact.target_type == "iam_user":
                fact_type = FactType.SECRET_CONTAINS_AWS_CREDENTIALS.value
                object_id = self.id_gen.iam_user(
                    aws_scan.get("aws_account_id", ""),
                    cred_fact.target_id
                )
            elif cred_fact.target_type == "rds":
                fact_type = FactType.SECRET_CONTAINS_CREDENTIALS.value
                object_id = self.id_gen.rds(
                    aws_scan.get("aws_account_id", ""),
                    cred_fact.target_id
                )
            elif cred_fact.target_type == "s3":
                fact_type = FactType.SECRET_CONTAINS_CREDENTIALS.value
                object_id = self.id_gen.s3_bucket(
                    aws_scan.get("aws_account_id", ""),
                    cred_fact.target_id
                )
            else:
                continue
            
            facts.append(Fact(
                fact_type=fact_type,
                subject_id=self.id_gen.secret(
                    cred_fact.secret_namespace,
                    cred_fact.secret_name
                ),
                subject_type=NodeType.SECRET.value,
                object_id=object_id,
                object_type=cred_fact.target_type,
                metadata={
                    "matched_keys": cred_fact.matched_keys,
                    "confidence": cred_fact.confidence,
                },
            ))
        
        return facts
    
    def _extract_iam_role_access_facts(self, aws_scan: Any) -> List[Fact]:
        """Extract IAM role access facts"""
        facts: List[Fact] = []
        
        account_id = aws_scan.get("aws_account_id", "")
        iam_roles = aws_scan.get("iam_roles", [])
        
        if not iam_roles:
            return facts
        
        # Parse IAM policies using existing parser
        try:
            from src.graph.builders.aws_scanner_types import IAMRoleScan
            
            role_scans = [IAMRoleScan(**role) if isinstance(role, dict) else role 
                         for role in iam_roles]
            policy_results = parse_all_roles(role_scans)
        except Exception as e:
            self.logger.error(f"Failed to parse IAM roles: {e}")
            return facts
        
        # Convert to facts
        for result in policy_results:
            role_id = self.id_gen.iam_role(account_id, result.role_name)
            
            for access in result.resource_access:
                # Determine target node ID
                target_ids = self._resolve_resource_targets(
                    access.service, access.resource_arns, account_id, aws_scan
                )
                
                for target_id, target_type in target_ids:
                    facts.append(Fact(
                        fact_type=FactType.IAM_ROLE_ACCESS_RESOURCE.value,
                        subject_id=role_id,
                        subject_type=NodeType.IAM_ROLE.value,
                        object_id=target_id,
                        object_type=target_type,
                        metadata={
                            "actions": access.actions,
                            "is_wildcard_action": access.is_wildcard_action,
                            "is_wildcard_resource": access.is_wildcard_resource,
                            "policy_name": access.policy_name,
                            "policy_arn": access.policy_arn,
                        },
                    ))
        
        return facts
    
    def _extract_iam_user_access_facts(self, aws_scan: Any) -> List[Fact]:
        """Extract IAM user access facts"""
        facts: List[Fact] = []
        
        account_id = aws_scan.get("aws_account_id", "")
        iam_users = aws_scan.get("iam_users", [])
        
        if not iam_users:
            return facts
        
        # Parse IAM user policies
        try:
            from src.graph.builders.aws_scanner_types import IAMUserScan
            
            user_scans = [IAMUserScan(**user) if isinstance(user, dict) else user 
                         for user in iam_users]
            user_policy_results = parse_all_users(user_scans)
        except Exception as e:
            self.logger.error(f"Failed to parse IAM users: {e}")
            return facts
        
        # Convert to facts
        for result in user_policy_results:
            user_id = self.id_gen.iam_user(account_id, result.username)
            
            for access in result.resource_access:
                target_ids = self._resolve_resource_targets(
                    access.service, access.resource_arns, account_id, aws_scan
                )
                
                for target_id, target_type in target_ids:
                    facts.append(Fact(
                        fact_type=FactType.IAM_USER_ACCESS_RESOURCE.value,
                        subject_id=user_id,
                        subject_type=NodeType.IAM_USER.value,
                        object_id=target_id,
                        object_type=target_type,
                        metadata={
                            "actions": access.actions,
                            "is_wildcard_action": access.is_wildcard_action,
                            "is_wildcard_resource": access.is_wildcard_resource,
                            "policy_name": access.policy_name,
                        },
                    ))
        
        return facts
    
    def _extract_security_group_facts(self, aws_scan: Any) -> List[Fact]:
        """Extract security group facts"""
        facts: List[Fact] = []
        
        account_id = aws_scan.get("aws_account_id", "")
        
        # RDS → Security Group
        for rds in aws_scan.get("rds_instances", []):
            rds_id = self.id_gen.rds(account_id, rds.get("identifier"))
            
            for sg_id in rds.get("vpc_security_groups", []):
                facts.append(Fact(
                    fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
                    subject_id=self.id_gen.security_group(account_id, sg_id),
                    subject_type=NodeType.SECURITY_GROUP.value,
                    object_id=rds_id,
                    object_type=NodeType.RDS.value,
                    metadata={"resource_type": "rds"},
                ))
        
        # EC2 → Security Group
        for ec2 in aws_scan.get("ec2_instances", []):
            ec2_id = self.id_gen.ec2_instance(account_id, ec2.get("instance_id"))
            
            for sg_id in ec2.get("security_groups", []):
                facts.append(Fact(
                    fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
                    subject_id=self.id_gen.security_group(account_id, sg_id),
                    subject_type=NodeType.SECURITY_GROUP.value,
                    object_id=ec2_id,
                    object_type=NodeType.EC2_INSTANCE.value,
                    metadata={"resource_type": "ec2"},
                ))
        
        return facts
    
    def _extract_instance_profile_facts(self, aws_scan: Any) -> List[Fact]:
        """Extract EC2 instance profile facts"""
        facts: List[Fact] = []
        
        account_id = aws_scan.get("aws_account_id", "")
        
        for ec2 in aws_scan.get("ec2_instances", []):
            instance_profile = ec2.get("iam_instance_profile")
            if not instance_profile:
                continue
            
            profile_arn = instance_profile.get("Arn", "")
            if not profile_arn:
                continue
            
            # Extract role name from ARN
            role_name = profile_arn.split("/")[-1]
            
            facts.append(Fact(
                fact_type=FactType.INSTANCE_PROFILE_ASSUMES.value,
                subject_id=self.id_gen.ec2_instance(account_id, ec2.get("instance_id")),
                subject_type=NodeType.EC2_INSTANCE.value,
                object_id=self.id_gen.iam_role(account_id, role_name),
                object_type=NodeType.IAM_ROLE.value,
                metadata={
                    "profile_arn": profile_arn,
                    "via": "instance_profile",
                },
            ))
        
        return facts
    
    def _resolve_resource_targets(
        self,
        service: str,
        resource_arns: List[str],
        account_id: str,
        aws_scan: Any,
    ) -> List[tuple[str, str]]:
        """Resolve resource ARNs to node IDs"""
        targets = []
        
        if service == "s3":
            # Wildcard or specific buckets
            if any("*" in arn for arn in resource_arns):
                # Wildcard - include all scanned buckets
                for bucket in aws_scan.get("s3_buckets", []):
                    targets.append((
                        self.id_gen.s3_bucket(account_id, bucket.get("name")),
                        NodeType.S3_BUCKET.value
                    ))
            else:
                # Specific ARNs
                for arn in resource_arns:
                    bucket_name = arn.split(":::")[-1].split("/")[0]
                    targets.append((
                        self.id_gen.s3_bucket(account_id, bucket_name),
                        NodeType.S3_BUCKET.value
                    ))
        
        elif service == "rds":
            # Wildcard or specific instances
            if any("*" in arn for arn in resource_arns):
                for rds in aws_scan.get("rds_instances", []):
                    targets.append((
                        self.id_gen.rds(account_id, rds.get("identifier")),
                        NodeType.RDS.value
                    ))
            else:
                for arn in resource_arns:
                    db_id = arn.split(":")[-1]
                    targets.append((
                        self.id_gen.rds(account_id, db_id),
                        NodeType.RDS.value
                    ))
        
        return targets