from typing import Any, Dict, List, Tuple

from src.facts.extractors.base_extractor import BaseExtractor
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.facts.id_generator import NodeIDGenerator

# Existing builders / parsers
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder
from src.graph.builders.iam_policy_parser import parse_all_roles, parse_all_users
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    IAMRoleScan,
    IAMUserScan,
    S3BucketScan,
    RDSInstanceScan,
    EC2InstanceScan,
    SecurityGroupScan,
    AccessKeyScan,
)


class AWSFactExtractor(BaseExtractor):
    """
    Extract AWS facts by wrapping existing builders.
    Also exposes bridge output for debug/test harnesses.

    Important:
    - Raw scan JSON is NOT the source of truth for downstream builders.
    - This extractor is the source of truth.
    - Therefore raw dict input is normalized here into the exact dataclass
      shapes expected by IRSA bridge builders and IAM policy parsers.
    """

    def __init__(self):
        super().__init__("aws")
        self.id_gen = NodeIDGenerator()
        self.bridge_builder = IRSABridgeBuilder()

    def extract(self, scan_data: Dict[str, Any], **kwargs) -> List[Fact]:
        facts, _bridge_output = self.extract_with_debug(scan_data, **kwargs)
        return facts

    def extract_with_debug(
        self, scan_data: Dict[str, Any], **kwargs
    ) -> Tuple[List[Fact], Dict[str, Any]]:
        """
        Extract AWS facts plus debug-friendly bridge output.

        Args:
            scan_data: raw AWS scanner output dict OR AWSScanResult
            **kwargs: must include k8s_scan for cross-domain facts

        Returns:
            (facts, bridge_output)
        """
        scan_id = (
            scan_data.get("scan_id", "unknown")
            if isinstance(scan_data, dict)
            else getattr(scan_data, "scan_id", "unknown")
        )
        self._log_extraction_start(scan_id)

        facts: List[Fact] = []
        bridge_output: Dict[str, Any] = {
            "irsa_mappings": [],
            "credential_facts": [],
            "warnings": [],
        }

        try:
            aws_scan = self._parse_aws_scan(scan_data)
            k8s_scan = kwargs.get("k8s_scan")

            if not k8s_scan:
                self.logger.warning(
                    "K8s scan not provided, skipping cross-domain facts",
                    scan_id=scan_id,
                )
                return facts, bridge_output

            cross_domain_facts, bridge_output = self._extract_cross_domain_facts(
                k8s_scan, aws_scan
            )
            facts.extend(cross_domain_facts)

            facts.extend(self._extract_iam_role_access_facts(aws_scan))
            facts.extend(self._extract_iam_user_access_facts(aws_scan))
            facts.extend(self._extract_explicit_assume_role_facts(aws_scan))
            facts.extend(self._extract_security_group_facts(aws_scan))
            facts.extend(self._extract_instance_profile_facts(aws_scan))

            self._log_extraction_complete(scan_id, len(facts))

        except Exception as e:
            self._log_error(scan_id, e, {"phase": "aws_extraction"})
            raise

        return facts, bridge_output

    def _extract_explicit_assume_role_facts(self, aws_scan: AWSScanResult) -> List[Fact]:
        facts: List[Fact] = []
        account_id = aws_scan.aws_account_id
        if not account_id:
            return facts

        scanned_roles_by_arn = {
            role.arn: role
            for role in aws_scan.iam_roles
            if isinstance(role.arn, str) and role.arn
        }
        if not scanned_roles_by_arn:
            return facts

        seen_keys: set[tuple[str, str, str]] = set()

        try:
            role_results = parse_all_roles(aws_scan.iam_roles) if aws_scan.iam_roles else []
        except Exception as e:
            self.logger.error(f"Failed to parse IAM roles for explicit AssumeRole detection: {e}")
            role_results = []

        try:
            user_results = parse_all_users(aws_scan.iam_users) if aws_scan.iam_users else []
        except Exception as e:
            self.logger.error(f"Failed to parse IAM users for explicit AssumeRole detection: {e}")
            user_results = []

        role_arn_by_name = {
            role.name: role.arn
            for role in aws_scan.iam_roles
            if isinstance(role.name, str) and role.name and isinstance(role.arn, str) and role.arn
        }
        user_arn_by_name = {
            user.username: user.arn
            for user in aws_scan.iam_users
            if isinstance(user.username, str) and user.username and isinstance(user.arn, str) and user.arn
        }

        for result in role_results:
            source_arn = role_arn_by_name.get(result.role_name)
            if not source_arn:
                continue
            source_id = self.id_gen.iam_role(account_id, result.role_name)
            self._append_explicit_assume_role_facts(
                facts,
                seen_keys=seen_keys,
                resource_access=result.resource_access,
                source_id=source_id,
                source_type=NodeType.IAM_ROLE.value,
                source_principal_arn=source_arn,
                current_account_id=account_id,
                scanned_roles_by_arn=scanned_roles_by_arn,
            )

        for result in user_results:
            source_arn = user_arn_by_name.get(result.username)
            if not source_arn:
                continue
            source_id = self.id_gen.iam_user(account_id, result.username)
            self._append_explicit_assume_role_facts(
                facts,
                seen_keys=seen_keys,
                resource_access=result.resource_access,
                source_id=source_id,
                source_type=NodeType.IAM_USER.value,
                source_principal_arn=source_arn,
                current_account_id=account_id,
                scanned_roles_by_arn=scanned_roles_by_arn,
            )

        return facts

    def _append_explicit_assume_role_facts(
        self,
        facts: List[Fact],
        *,
        seen_keys: set[tuple[str, str, str]],
        resource_access: List[Any],
        source_id: str,
        source_type: str,
        source_principal_arn: str,
        current_account_id: str,
        scanned_roles_by_arn: Dict[str, IAMRoleScan],
    ) -> None:
        for access in resource_access:
            if access.effect != "Allow" or access.service != "sts":
                continue
            if not self._resource_access_allows_explicit_assume_role(access):
                continue

            for target_role_arn in access.resource_arns:
                if not self._is_explicit_same_account_role_arn(
                    target_role_arn,
                    account_id=current_account_id,
                ):
                    continue

                target_role = scanned_roles_by_arn.get(target_role_arn)
                if target_role is None:
                    continue

                if not self._trust_policy_explicitly_allows_principal(
                    target_role.trust_policy,
                    source_principal_arn,
                ):
                    continue

                target_role_name = target_role_arn.rsplit("/", 1)[-1]
                fact_key = (
                    source_id,
                    self.id_gen.iam_role(current_account_id, target_role_name),
                    FactType.IAM_PRINCIPAL_ASSUMES_IAM_ROLE.value,
                )
                if fact_key in seen_keys:
                    continue
                seen_keys.add(fact_key)

                facts.append(
                    Fact(
                        fact_type=FactType.IAM_PRINCIPAL_ASSUMES_IAM_ROLE.value,
                        subject_id=source_id,
                        subject_type=source_type,
                        object_id=self.id_gen.iam_role(current_account_id, target_role_name),
                        object_type=NodeType.IAM_ROLE.value,
                        metadata={
                            "source_principal_arn": source_principal_arn,
                            "target_role_arn": target_role_arn,
                            "via": "explicit_sts_assumerole",
                        },
                    )
                )

    @staticmethod
    def _resource_access_allows_explicit_assume_role(access: Any) -> bool:
        if getattr(access, "is_wildcard_resource", False):
            return False

        actions = {
            str(action).strip().lower()
            for action in getattr(access, "actions", [])
            if isinstance(action, str) and action.strip()
        }
        return "sts:assumerole" in actions

    @staticmethod
    def _is_explicit_same_account_role_arn(role_arn: Any, *, account_id: str) -> bool:
        if not isinstance(role_arn, str) or not role_arn or "*" in role_arn:
            return False

        parts = role_arn.split(":", 5)
        if len(parts) != 6:
            return False
        if parts[1] != "aws" or parts[2] != "iam" or parts[4] != account_id:
            return False

        resource = parts[5]
        if not resource.startswith("role/"):
            return False

        role_name = resource[len("role/"):]
        return bool(role_name)

    @staticmethod
    def _trust_policy_explicitly_allows_principal(
        trust_policy: Dict[str, Any],
        source_principal_arn: str,
    ) -> bool:
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return False

        for statement in statements:
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            if statement.get("Condition"):
                continue
            principal = statement.get("Principal")
            if not isinstance(principal, dict):
                continue
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            if not isinstance(aws_principals, list):
                continue
            if any(principal_arn == source_principal_arn for principal_arn in aws_principals):
                return True
        return False

    def _parse_aws_scan(self, scan_data: Dict[str, Any] | AWSScanResult) -> AWSScanResult:
        """
        Normalize raw AWS scan dict into the dataclass shapes expected by:
        - IRSABridgeBuilder
        - parse_all_roles / parse_all_users

        This is the correct fix point for raw-vs-builder schema mismatch.
        """
        if isinstance(scan_data, AWSScanResult):
            return scan_data

        return AWSScanResult(
            scan_id=scan_data.get("scan_id", "unknown"),
            aws_account_id=scan_data.get("aws_account_id", ""),
            region=scan_data.get("region"),
            scanned_at=scan_data.get("scanned_at", ""),
            iam_roles=[
                role if isinstance(role, IAMRoleScan) else IAMRoleScan(
                    name=role.get("name") or role.get("role_name", ""),
                    arn=role.get("arn", ""),
                    is_irsa=role.get("is_irsa", False),
                    irsa_oidc_issuer=role.get("irsa_oidc_issuer"),
                    attached_policies=role.get("attached_policies", []),
                    inline_policies=role.get("inline_policies", []),
                    trust_policy=role.get("trust_policy", {}),
                )
                for role in scan_data.get("iam_roles", [])
            ],
            iam_users=[
                user if isinstance(user, IAMUserScan) else IAMUserScan(
                    username=user.get("username", ""),
                    arn=user.get("arn", ""),
                    access_keys=[
                        ak if isinstance(ak, AccessKeyScan) else AccessKeyScan(
                            access_key_id=ak.get("access_key_id", ""),
                            status=ak.get("status", ""),
                            create_date=ak.get("create_date", ""),
                        )
                        for ak in user.get("access_keys", [])
                    ],
                    attached_policies=user.get("attached_policies", []),
                    inline_policies=user.get("inline_policies", []),
                    has_mfa=user.get("has_mfa", False),
                    last_used=user.get("last_used"),
                )
                for user in scan_data.get("iam_users", [])
            ],
            s3_buckets=[
                bucket if isinstance(bucket, S3BucketScan) else S3BucketScan(
                    name=bucket.get("name", ""),
                    arn=bucket.get("arn", ""),
                    public_access_block=bucket.get("public_access_block"),
                    encryption=bucket.get("encryption"),
                    versioning=bucket.get("versioning", "Unknown"),
                    logging_enabled=bucket.get("logging_enabled", False),
                )
                for bucket in scan_data.get("s3_buckets", [])
            ],
            rds_instances=[
                rds if isinstance(rds, RDSInstanceScan) else RDSInstanceScan(
                    identifier=rds.get("identifier", ""),
                    arn=rds.get("arn", ""),
                    engine=rds.get("engine", ""),
                    engine_version=rds.get("engine_version"),
                    storage_encrypted=rds.get("storage_encrypted", False),
                    publicly_accessible=rds.get("publicly_accessible", False),
                    vpc_security_groups=rds.get("vpc_security_groups", []),
                    endpoint=rds.get("endpoint"),
                )
                for rds in scan_data.get("rds_instances", [])
            ],
            ec2_instances=[
                ec2 if isinstance(ec2, EC2InstanceScan) else EC2InstanceScan(
                    instance_id=ec2.get("instance_id", ""),
                    instance_type=ec2.get("instance_type", ""),
                    metadata_options=ec2.get("metadata_options", {}),
                    iam_instance_profile=ec2.get("iam_instance_profile"),
                    security_groups=ec2.get("security_groups", []),
                    tags=ec2.get("tags", {}),
                )
                for ec2 in scan_data.get("ec2_instances", [])
            ],
            security_groups=[
                sg if isinstance(sg, SecurityGroupScan) else SecurityGroupScan(
                    group_id=sg.get("group_id", ""),
                    group_name=sg.get("group_name", ""),
                    vpc_id=sg.get("vpc_id", ""),
                    inbound_rules=sg.get("inbound_rules", []),
                    outbound_rules=sg.get("outbound_rules", []),
                )
                for sg in scan_data.get("security_groups", [])
            ],
        )

    def _extract_cross_domain_facts(
        self, k8s_scan: Dict[str, Any], aws_scan: AWSScanResult
    ) -> Tuple[List[Fact], Dict[str, Any]]:
        facts: List[Fact] = []

        bridge_result = self.bridge_builder.build(k8s_scan, aws_scan)
        bridge_output = self._serialize_bridge_result(bridge_result)

        # IRSA mappings -> facts
        for mapping in getattr(bridge_result, "irsa_mappings", []):
            facts.append(
                Fact(
                    fact_type=FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
                    subject_id=self.id_gen.service_account(
                        mapping.sa_namespace, mapping.sa_name
                    ),
                    subject_type=NodeType.SERVICE_ACCOUNT.value,
                    object_id=self.id_gen.iam_role(
                        mapping.account_id, mapping.iam_role_name
                    ),
                    object_type=NodeType.IAM_ROLE.value,
                    metadata={
                        "annotation": "eks.amazonaws.com/role-arn",
                        "role_arn": mapping.iam_role_arn,
                        "via": "irsa",
                    },
                )
            )

        account_id = aws_scan.aws_account_id

        # Secret credential facts -> facts
        for cred_fact in getattr(bridge_result, "credential_facts", []):
            if cred_fact.target_type == "iam_user":
                fact_type = FactType.SECRET_CONTAINS_AWS_CREDENTIALS.value
                object_id = self.id_gen.iam_user(account_id, cred_fact.target_id)
                object_type = NodeType.IAM_USER.value

            elif cred_fact.target_type == "rds":
                fact_type = FactType.SECRET_CONTAINS_CREDENTIALS.value
                object_id = self.id_gen.rds(account_id, cred_fact.target_id)
                object_type = NodeType.RDS.value

            elif cred_fact.target_type == "s3":
                fact_type = FactType.SECRET_CONTAINS_CREDENTIALS.value
                object_id = self.id_gen.s3_bucket(account_id, cred_fact.target_id)
                object_type = NodeType.S3_BUCKET.value

            else:
                continue

            facts.append(
                Fact(
                    fact_type=fact_type,
                    subject_id=self.id_gen.secret(
                        cred_fact.secret_namespace,
                        cred_fact.secret_name,
                    ),
                    subject_type=NodeType.SECRET.value,
                    object_id=object_id,
                    object_type=object_type,
                    metadata={
                        "matched_keys": cred_fact.matched_keys,
                        "confidence": cred_fact.confidence,
                    },
                )
            )

        return facts, bridge_output

    def _extract_iam_role_access_facts(self, aws_scan: AWSScanResult) -> List[Fact]:
        facts: List[Fact] = []

        account_id = aws_scan.aws_account_id
        iam_roles = aws_scan.iam_roles

        if not iam_roles:
            return facts

        try:
            policy_results = parse_all_roles(iam_roles)
        except Exception as e:
            self.logger.error(f"Failed to parse IAM roles: {e}")
            return facts

        for result in policy_results:
            role_id = self.id_gen.iam_role(account_id, result.role_name)

            for access in result.resource_access:
                target_ids = self._resolve_resource_targets(
                    access.service,
                    access.resource_arns,
                    account_id,
                    aws_scan,
                )

                for target_id, target_type in target_ids:
                    facts.append(
                        Fact(
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
                        )
                    )

        return facts

    def _extract_iam_user_access_facts(self, aws_scan: AWSScanResult) -> List[Fact]:
        facts: List[Fact] = []

        account_id = aws_scan.aws_account_id
        iam_users = aws_scan.iam_users

        if not iam_users:
            return facts

        try:
            user_policy_results = parse_all_users(iam_users)
        except Exception as e:
            self.logger.error(f"Failed to parse IAM users: {e}")
            return facts

        for result in user_policy_results:
            user_id = self.id_gen.iam_user(account_id, result.username)

            for access in result.resource_access:
                target_ids = self._resolve_resource_targets(
                    access.service,
                    access.resource_arns,
                    account_id,
                    aws_scan,
                )

                for target_id, target_type in target_ids:
                    facts.append(
                        Fact(
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
                        )
                    )

        return facts

    def _extract_security_group_facts(self, aws_scan: AWSScanResult) -> List[Fact]:
        facts: List[Fact] = []

        account_id = aws_scan.aws_account_id

        # RDS -> Security Group
        for rds in aws_scan.rds_instances:
            rds_id = self.id_gen.rds(account_id, rds.identifier)

            for sg_id in rds.vpc_security_groups:
                facts.append(
                    Fact(
                        fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
                        subject_id=self.id_gen.security_group(account_id, sg_id),
                        subject_type=NodeType.SECURITY_GROUP.value,
                        object_id=rds_id,
                        object_type=NodeType.RDS.value,
                        metadata={"resource_type": "rds"},
                    )
                )

        # EC2 -> Security Group
        for ec2 in aws_scan.ec2_instances:
            ec2_id = self.id_gen.ec2_instance(account_id, ec2.instance_id)

            for sg_id in ec2.security_groups:
                facts.append(
                    Fact(
                        fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
                        subject_id=self.id_gen.security_group(account_id, sg_id),
                        subject_type=NodeType.SECURITY_GROUP.value,
                        object_id=ec2_id,
                        object_type=NodeType.EC2_INSTANCE.value,
                        metadata={"resource_type": "ec2"},
                    )
                )

        return facts

    def _extract_instance_profile_facts(self, aws_scan: AWSScanResult) -> List[Fact]:
        facts: List[Fact] = []

        account_id = aws_scan.aws_account_id

        for ec2 in aws_scan.ec2_instances:
            instance_profile = ec2.iam_instance_profile
            if not instance_profile:
                continue

            profile_arn = instance_profile.get("Arn", "")
            if not profile_arn:
                continue

            role_name = profile_arn.split("/")[-1]

            facts.append(
                Fact(
                    fact_type=FactType.INSTANCE_PROFILE_ASSUMES.value,
                    subject_id=self.id_gen.ec2_instance(account_id, ec2.instance_id),
                    subject_type=NodeType.EC2_INSTANCE.value,
                    object_id=self.id_gen.iam_role(account_id, role_name),
                    object_type=NodeType.IAM_ROLE.value,
                    metadata={
                        "profile_arn": profile_arn,
                        "via": "instance_profile",
                    },
                )
            )

        return facts

    def _resolve_resource_targets(
        self,
        service: str,
        resource_arns: List[str],
        account_id: str,
        aws_scan: AWSScanResult,
    ) -> List[tuple[str, str]]:
        targets = []

        if service == "s3":
            if any("*" in arn for arn in resource_arns):
                for bucket in aws_scan.s3_buckets:
                    targets.append(
                        (
                            self.id_gen.s3_bucket(account_id, bucket.name),
                            NodeType.S3_BUCKET.value,
                        )
                    )
            else:
                for arn in resource_arns:
                    bucket_name = arn.split(":::")[-1].split("/")[0]
                    targets.append(
                        (
                            self.id_gen.s3_bucket(account_id, bucket_name),
                            NodeType.S3_BUCKET.value,
                        )
                    )

        elif service == "rds":
            if any("*" in arn for arn in resource_arns):
                for rds in aws_scan.rds_instances:
                    targets.append(
                        (
                            self.id_gen.rds(account_id, rds.identifier),
                            NodeType.RDS.value,
                        )
                    )
            else:
                for arn in resource_arns:
                    db_id = arn.split(":")[-1]
                    targets.append(
                        (
                            self.id_gen.rds(account_id, db_id),
                            NodeType.RDS.value,
                        )
                    )

        return targets

    def _serialize_bridge_result(self, bridge_result: Any) -> Dict[str, Any]:
        return {
            "irsa_mappings": [
                {
                    "sa_namespace": x.sa_namespace,
                    "sa_name": x.sa_name,
                    "iam_role_arn": x.iam_role_arn,
                    "iam_role_name": x.iam_role_name,
                    "account_id": x.account_id,
                }
                for x in getattr(bridge_result, "irsa_mappings", [])
            ],
            "credential_facts": [
                {
                    "secret_namespace": x.secret_namespace,
                    "secret_name": x.secret_name,
                    "target_type": x.target_type,
                    "target_id": x.target_id,
                    "matched_keys": list(x.matched_keys),
                    "confidence": x.confidence,
                }
                for x in getattr(bridge_result, "credential_facts", [])
            ],
            "warnings": getattr(bridge_result, "warnings", []),
            "skipped_irsa": getattr(bridge_result, "skipped_irsa", None),
            "skipped_credentials": getattr(bridge_result, "skipped_credentials", None),
        }
