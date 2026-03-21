"""AWS Graph Builder base structure with core data classes."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Optional

from src.graph.builders.aws_scanner_types import AWSScanResult, EC2InstanceScan, IAMRoleScan, IAMUserScan, RDSInstanceScan, S3BucketScan, SecurityGroupScan
from src.graph.builders.cross_domain_types import BridgeResult, IRSAMapping, SecretContainsCredentialsFact
from src.graph.builders.iam_policy_types import IAMPolicyAnalysisResult, IAMUserPolicyAnalysisResult

if TYPE_CHECKING:
    from src.graph.builders.build_result_types import AWSBuildResult


@dataclass
class GraphNode:
    """Represents a node in the AWS resource graph.

    Attributes:
        id: Unique identifier in the format "type:account_id:resource_name".
        type: The AWS resource type (e.g., "s3", "lambda", "iam_role").
        namespace: The account or namespace this resource belongs to.
        is_entry_point: Whether this node is an entry point for attackers.
        is_crown_jewel: Whether this node is a high-value target.
        metadata: Additional resource metadata including scan_id and ARN.
    """

    id: str
    type: str
    namespace: Optional[str]
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a directed edge between two nodes in the AWS resource graph.

    Attributes:
        source: The ID of the source GraphNode.
        target: The ID of the target GraphNode.
        type: The relationship type (e.g., "can_invoke", "has_policy", "assumes").
        metadata: Additional edge metadata.
    """

    source: str
    target: str
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphMetadata:
    """Graph-level metadata required by the AWS graph contract."""

    graph_id: str
    scan_id: str
    account_id: str
    generated_at: str


class AWSGraphBuilder:
    """Builds a graph of AWS resources and their relationships.

    The graph is composed of GraphNode and GraphEdge objects representing
    AWS resources and the connections between them.

    Attributes:
        account_id: The AWS account ID being scanned.
        scan_id: The unique identifier for this scan run.
        nodes: List of all graph nodes.
        edges: List of all graph edges.
        _node_ids: Set of node IDs for duplicate prevention.
    """

    def __init__(self, account_id: str, scan_id: str) -> None:
        """Initialize the AWSGraphBuilder.

        Args:
            account_id: The AWS account ID being scanned.
            scan_id: The unique identifier for this scan run.
        """
        self.account_id = account_id
        self.scan_id = scan_id
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self._node_ids: set[str] = set()
        self.graph_metadata: Optional[GraphMetadata] = None

    def _add_node(self, node: GraphNode) -> None:
        """Add a node to the graph, preventing duplicates.

        If a node with the same ID already exists, it will not be added again.

        Args:
            node: The GraphNode to add.
        """
        if node.id not in self._node_ids:
            self._node_ids.add(node.id)
            self.nodes.append(node)

    def _timestamp(self) -> str:
        """Return a UTC timestamp in ISO 8601 format."""
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _policy_name(self, policy: dict[str, Any]) -> Optional[str]:
        return policy.get("PolicyName") or policy.get("name")

    def _graph_metadata(self) -> GraphMetadata:
        generated_at = self._timestamp()
        return GraphMetadata(
            graph_id=f"{self.scan_id}-graph",
            scan_id=self.scan_id,
            account_id=self.account_id,
            generated_at=generated_at,
        )

    def _security_group_edge_metadata(self, sg: Optional[SecurityGroupScan], resource_type: str) -> dict[str, Any]:
        rules = sg.inbound_rules if sg else []
        is_public = False
        open_ports: list[int] = []

        for rule in rules:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    is_public = True
                    from_port = rule.get("FromPort")
                    if isinstance(from_port, int):
                        open_ports.append(from_port)

        return {
            "resource_type": resource_type,
            "rules": rules,
            "is_public": is_public,
            "open_ports": open_ports,
            "scan_id": self.scan_id,
            "source_type": "aws_scanner",
            "created_at": self._timestamp(),
        }

    def _build_s3_nodes(self, buckets: list[S3BucketScan]) -> None:
        """Build graph nodes for S3 buckets.

        Args:
            buckets: List of S3BucketScan objects to process.
        """
        for bucket in buckets:
            is_public = (
                bucket.public_access_block is not None
                and bucket.public_access_block.get("BlockPublicAcls") is False
            )
            has_encryption = bucket.encryption is not None

            compliance_violations = []
            if is_public:
                compliance_violations.append("PISM-005")
            if not has_encryption:
                compliance_violations.append("PISM-029")

            node = GraphNode(
                id=f"s3:{self.account_id}:{bucket.name}",
                type="s3_bucket",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=True,
                metadata={
                    "arn": bucket.arn,
                    "is_public": is_public,
                    "has_encryption": has_encryption,
                    "versioning": bucket.versioning,
                    "compliance_violations": compliance_violations,
                    "scan_id": self.scan_id,
                },
            )
            self._add_node(node)

    def _build_rds_nodes(self, instances: list[RDSInstanceScan]) -> None:
        """Build graph nodes for RDS instances.

        Args:
            instances: List of RDSInstanceScan objects to process.
        """
        for rds in instances:
            compliance_violations = []
            if not rds.storage_encrypted:
                compliance_violations.append("PISM-034")
            if rds.publicly_accessible:
                compliance_violations.append("PISM-007")

            node = GraphNode(
                id=f"rds:{self.account_id}:{rds.identifier}",
                type="rds",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=True,
                metadata={
                    "arn": rds.arn,
                    "engine": rds.engine,
                    "storage_encrypted": rds.storage_encrypted,
                    "publicly_accessible": rds.publicly_accessible,
                    "security_groups": rds.vpc_security_groups,
                    "compliance_violations": compliance_violations,
                    "scan_id": self.scan_id,
                },
            )
            self._add_node(node)

    def _build_security_group_nodes(self, sgs: list[SecurityGroupScan]) -> None:
        """Build graph nodes for Security Groups.

        Args:
            sgs: List of SecurityGroupScan objects to process.
        """
        for sg in sgs:
            is_publicly_accessible = False
            open_ports = []

            for rule in sg.inbound_rules:
                ip_ranges = rule.get("IpRanges", [])
                for ip_range in ip_ranges:
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        is_publicly_accessible = True
                        from_port = rule.get("FromPort")
                        if from_port is not None:
                            open_ports.append(from_port)

            compliance_violations = []
            if is_publicly_accessible:
                compliance_violations.append("PISM-007")

            node = GraphNode(
                id=f"sg:{self.account_id}:{sg.group_id}",
                type="security_group",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=False,
                metadata={
                    "group_name": sg.group_name,
                    "is_publicly_accessible": is_publicly_accessible,
                    "open_ports": open_ports,
                    "compliance_violations": compliance_violations,
                    "scan_id": self.scan_id,
                },
            )
            self._add_node(node)

    def _build_ec2_nodes(self, instances: list[EC2InstanceScan]) -> None:
        """Build graph nodes for EC2 instances.

        Args:
            instances: List of EC2InstanceScan objects to process.
        """
        for ec2 in instances:
            http_tokens = ec2.metadata_options.get("HttpTokens", "optional") if ec2.metadata_options else "optional"
            imds_v1_enabled = http_tokens == "optional"

            has_instance_profile = ec2.iam_instance_profile is not None
            instance_profile_role = None
            if has_instance_profile:
                arn = ec2.iam_instance_profile.get("Arn", "")
                if arn:
                    instance_profile_role = arn.split("/")[-1]

            compliance_violations = []
            if imds_v1_enabled:
                compliance_violations.append("PISM-064")

            node = GraphNode(
                id=f"ec2:{self.account_id}:{ec2.instance_id}",
                type="ec2_instance",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=False,
                metadata={
                    "imds_v1_enabled": imds_v1_enabled,
                    "http_tokens": http_tokens,
                    "has_instance_profile": has_instance_profile,
                    "instance_profile_role": instance_profile_role,
                    "compliance_violations": compliance_violations,
                    "scan_id": self.scan_id,
                },
            )
            self._add_node(node)

    def _build_iam_role_nodes(
        self,
        roles: list[IAMRoleScan],
        policy_results: list[IAMPolicyAnalysisResult] | None = None,
    ) -> None:
        """Build graph nodes for IAM Roles.

        Args:
            roles: List of IAMRoleScan objects to process.
            policy_results: Optional list of IAMPolicyAnalysisResult objects for tier classification.
        """
        policy_by_role = {r.role_name: r for r in policy_results} if policy_results else {}
        for role in roles:
            analysis = policy_by_role.get(role.name)
            is_crown_jewel = False
            metadata: dict[str, Any] = {
                "arn": role.arn,
                "is_irsa": role.is_irsa,
                "attached_policies": [
                    name for p in role.attached_policies
                    if (name := self._policy_name(p)) is not None
                ],
                "scan_id": self.scan_id,
            }
            if analysis:
                is_crown_jewel = analysis.tier in (1, 2)
                metadata["tier"] = analysis.tier
                metadata["tier_reason"] = analysis.tier_reason
                metadata["has_privilege_escalation"] = analysis.has_privilege_escalation
                metadata["has_data_exfiltration_risk"] = analysis.has_data_exfiltration_risk
                metadata["has_credential_access"] = analysis.has_credential_access
                metadata["trust"] = {
                    "is_irsa_enabled": analysis.trust_analysis.is_irsa_enabled,
                    "oidc_issuer": analysis.trust_analysis.oidc_issuer,
                    "allows_all_sa": analysis.trust_analysis.allows_all_sa,
                    "allowed_sa_patterns": analysis.trust_analysis.allowed_sa_patterns,
                    "allowed_sa_explicit": analysis.trust_analysis.allowed_sa_explicit,
                    "allows_ec2": analysis.trust_analysis.allows_ec2,
                    "allows_lambda": analysis.trust_analysis.allows_lambda,
                    "cross_account_principals": analysis.trust_analysis.cross_account_principals,
                }
            else:
                metadata["tier"] = None
                metadata["tier_reason"] = "policy_analysis_unavailable"
            node = GraphNode(
                id=f"iam:{self.account_id}:{role.name}",
                type="iam_role",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=is_crown_jewel,
                metadata=metadata,
            )
            self._add_node(node)

    def _build_iam_user_nodes(
        self,
        users: list[IAMUserScan],
        policy_results: list[IAMUserPolicyAnalysisResult] | None = None,
    ) -> None:
        """Build graph nodes for IAM Users.

        Args:
            users: List of IAMUserScan objects to process.
            policy_results: Optional list of IAMUserPolicyAnalysisResult objects (Step 3).
        """
        policy_by_user = {r.username: r for r in policy_results} if policy_results else {}

        for user in users:
            active_key_count = sum(1 for k in user.access_keys if k.status == "Active")
            has_active_key = active_key_count > 0

            compliance_violations: list[str] = []
            if not user.has_mfa and has_active_key:
                compliance_violations.append("PISM-IAM-001")
            if active_key_count > 1:
                compliance_violations.append("PISM-IAM-002")

            metadata: dict[str, Any] = {
                "arn": user.arn,
                "has_mfa": user.has_mfa,
                "has_active_key": has_active_key,
                "active_key_count": active_key_count,
                "last_used": user.last_used,
                "compliance_violations": compliance_violations,
                "scan_id": self.scan_id,
            }

            analysis = policy_by_user.get(user.username)
            is_crown_jewel = False
            if analysis:
                is_crown_jewel = analysis.tier in (1, 2)
                metadata["tier"] = analysis.tier
                metadata["tier_reason"] = analysis.tier_reason
                metadata["has_privilege_escalation"] = analysis.has_privilege_escalation

            node = GraphNode(
                id=f"iam_user:{self.account_id}:{user.username}",
                type="iam_user",
                namespace=self.account_id,
                is_entry_point=False,
                is_crown_jewel=is_crown_jewel,
                metadata=metadata,
            )
            self._add_node(node)

    def _build_sg_allows_edges(self, scan: AWSScanResult) -> None:
        """Build edges from Security Groups to RDS and EC2 instances.

        Args:
            scan: The AWSScanResult containing RDS and EC2 instances.
        """
        sg_by_id = {sg.group_id: sg for sg in scan.security_groups}
        for rds in scan.rds_instances:
            for sg_id in rds.vpc_security_groups:
                self._add_edge(GraphEdge(
                    source=f"sg:{self.account_id}:{sg_id}",
                    target=f"rds:{self.account_id}:{rds.identifier}",
                    type="security_group_allows",
                    metadata=self._security_group_edge_metadata(sg_by_id.get(sg_id), "rds"),
                ))

        for ec2 in scan.ec2_instances:
            for sg_id in ec2.security_groups:
                self._add_edge(GraphEdge(
                    source=f"sg:{self.account_id}:{sg_id}",
                    target=f"ec2:{self.account_id}:{ec2.instance_id}",
                    type="security_group_allows",
                    metadata=self._security_group_edge_metadata(sg_by_id.get(sg_id), "ec2"),
                ))

    def _build_instance_profile_edges(self, instances: list[EC2InstanceScan]) -> None:
        """Build edges from EC2 instances to IAM roles via instance profiles.

        Args:
            instances: List of EC2InstanceScan objects to process.
        """
        for ec2 in instances:
            if not ec2.iam_instance_profile:
                continue
            profile_arn = ec2.iam_instance_profile.get("Arn", "")
            if not profile_arn:
                continue
            role_name = profile_arn.split("/")[-1]
            self._add_edge(GraphEdge(
                source=f"ec2:{self.account_id}:{ec2.instance_id}",
                target=f"iam:{self.account_id}:{role_name}",
                type="instance_profile_assumes",
                metadata={
                    "profile_arn": profile_arn,
                    "role_name": role_name,
                    "via": "instance_profile",
                    "scan_id": self.scan_id,
                    "source_type": "aws_scanner",
                    "created_at": self._timestamp(),
                },
            ))

    def _build_irsa_edges(self, mappings: list[IRSAMapping]) -> None:
        """Build edges from Kubernetes service accounts to IAM roles via IRSA.

        Dangling edges are allowed — service account nodes may originate from
        the K8s Graph Builder and may not exist in this graph.

        Args:
            mappings: List of IRSAMapping objects to process.
        """
        for mapping in mappings:
            self._add_edge(GraphEdge(
                source=f"sa:{mapping.sa_namespace}:{mapping.sa_name}",
                target=f"iam:{mapping.account_id}:{mapping.iam_role_name}",
                type="service_account_assumes_iam_role",
                metadata={
                    "annotation_key": "eks.amazonaws.com/role-arn",
                    "annotation_value": mapping.iam_role_arn,
                    "role_arn": mapping.iam_role_arn,
                    "via": "irsa",
                    "scan_id": self.scan_id,
                    "source_type": "irsa_mapper",
                    "created_at": self._timestamp(),
                },
            ))

    def _build_credential_edges(self, credential_facts: list[SecretContainsCredentialsFact]) -> None:
        """Build edges from Kubernetes secrets to AWS resources they contain credentials for.

        Dangling edges are allowed — secret nodes may originate from the K8s
        Graph Builder and may not exist in this graph.

        Args:
            credential_facts: List of SecretContainsCredentialsFact objects to process.
        """
        for fact in credential_facts:
            edge_type = "secret_contains_aws_credentials" if fact.target_type == "iam_user" else "secret_contains_credentials"
            self._add_edge(GraphEdge(
                source=f"secret:{fact.secret_namespace}:{fact.secret_name}",
                target=f"{fact.target_type}:{self.account_id}:{fact.target_id}",
                type=edge_type,
                metadata={
                    "matched_keys": fact.matched_keys,
                    "confidence": fact.confidence,
                    "scan_id": self.scan_id,
                    "source_type": "credential_matcher",
                    "created_at": self._timestamp(),
                },
            ))

    def build(
        self,
        scan: AWSScanResult,
        irsa_mappings: list[IRSAMapping],
        credential_facts: list[SecretContainsCredentialsFact],
        policy_results: list[IAMPolicyAnalysisResult] | None = None,
        user_policy_results: list[IAMUserPolicyAnalysisResult] | None = None,
    ) -> "AWSBuildResult":
        """
        Build AWS graph nodes and edges from scan data.

        Args:
            scan: AWS Scanner output containing all resource data
            irsa_mappings: Service Account to IAM Role mappings from K8s Scanner
            credential_facts: Secret to AWS resource credential mappings
            policy_results: IAM Policy analysis results; when provided, IAM access
                edges are created linking roles to the S3/RDS resources they can access
            user_policy_results: IAM User Policy analysis results; when provided, IAM
                user access edges are created linking users to the S3/RDS resources
                they can access

        Returns:
            AWSBuildResult containing nodes, edges, and graph metadata.

        Implementation:
            - Creates nodes: IAM Role, IAM User, S3, RDS, SecurityGroup, EC2
            - Creates edges: SG allows, Instance Profile, IRSA, Credentials,
              IAM access edges (only when policy_results provided), and IAM user
              access edges (only when user_policy_results provided)
        """
        from src.graph.builders.build_result_types import AWSBuildResult

        # Nodes first
        self._build_iam_role_nodes(scan.iam_roles, policy_results)
        self._build_iam_user_nodes(scan.iam_users, user_policy_results)
        self._build_s3_nodes(scan.s3_buckets)
        self._build_rds_nodes(scan.rds_instances)
        self._build_security_group_nodes(scan.security_groups)
        self._build_ec2_nodes(scan.ec2_instances)

        # Then edges
        self._build_sg_allows_edges(scan)
        self._build_instance_profile_edges(scan.ec2_instances)
        self._build_irsa_edges(irsa_mappings)
        self._build_credential_edges(credential_facts)
        if policy_results:
            self._build_iam_access_edges(policy_results, scan)
        if user_policy_results:
            self._build_iam_user_access_edges(user_policy_results, scan)

        self.graph_metadata = self._graph_metadata()
        return AWSBuildResult(
            nodes=self.nodes,
            edges=self.edges,
            metadata={
                "graph_id": self.graph_metadata.graph_id,
                "scan_id": self.graph_metadata.scan_id,
                "account_id": self.graph_metadata.account_id,
            },
        )

    def build_with_bridge_result(
        self,
        scan: AWSScanResult,
        bridge_result: BridgeResult,
        policy_results: list[IAMPolicyAnalysisResult] | None = None,
        user_policy_results: list[IAMUserPolicyAnalysisResult] | None = None,
    ) -> "AWSBuildResult":
        """Compose AWS-owned graph output from AWS scan data and typed bridge inputs."""

        return self.build(
            scan=scan,
            irsa_mappings=bridge_result.irsa_mappings,
            credential_facts=bridge_result.credential_facts,
            policy_results=policy_results,
            user_policy_results=user_policy_results,
        )

    def _resolve_wildcard_targets(self, service: str, known_s3: set[str], known_rds: set[str]) -> list[str]:
        if service == "s3":
            return [f"s3:{self.account_id}:{name}" for name in known_s3]
        elif service == "rds":
            return [f"rds:{self.account_id}:{name}" for name in known_rds]
        return []

    def _resolve_specific_targets(self, service: str, arns: list[str], known_s3: set[str], known_rds: set[str]) -> list[str]:
        targets = []
        for arn in arns:
            if service == "s3":
                parts = arn.split(":::")
                if len(parts) == 2:
                    bucket_name = parts[1].split("/")[0]
                    if bucket_name in known_s3:
                        targets.append(f"s3:{self.account_id}:{bucket_name}")
            elif service == "rds":
                parts = arn.split(":")
                if len(parts) >= 7:
                    identifier = parts[6]
                    if identifier in known_rds:
                        targets.append(f"rds:{self.account_id}:{identifier}")
        return targets

    def _build_iam_access_edges(
        self,
        policy_results: list[IAMPolicyAnalysisResult],
        scan: AWSScanResult,
    ) -> None:
        known_s3 = {b.name for b in scan.s3_buckets}
        known_rds = {r.identifier for r in scan.rds_instances}

        for analysis in policy_results:
            source = f"iam:{self.account_id}:{analysis.role_name}"
            for resource_access in analysis.resource_access:
                if resource_access.effect == "Deny":
                    continue
                service = resource_access.service
                if service not in ("s3", "rds"):
                    continue
                if resource_access.is_wildcard_resource:
                    targets = self._resolve_wildcard_targets(service, known_s3, known_rds)
                else:
                    targets = self._resolve_specific_targets(service, resource_access.resource_arns, known_s3, known_rds)
                for target in targets:
                    self._add_edge(GraphEdge(
                        source=source,
                        target=target,
                        type="iam_role_access_resource",
                        metadata={
                            "service": service,
                            "actions": resource_access.actions,
                            "is_wildcard_action": resource_access.is_wildcard_action,
                            "is_wildcard_resource": resource_access.is_wildcard_resource,
                            "policy_name": resource_access.policy_name,
                            "policy_arn": resource_access.policy_arn,
                            "scan_id": self.scan_id,
                            "source_type": "iam_policy_parser",
                            "created_at": self._timestamp(),
                        },
                    ))

    def _build_iam_user_access_edges(
        self,
        user_policy_results: list[IAMUserPolicyAnalysisResult],
        scan: AWSScanResult,
    ) -> None:
        known_s3 = {b.name for b in scan.s3_buckets}
        known_rds = {r.identifier for r in scan.rds_instances}

        for analysis in user_policy_results:
            source = f"iam_user:{self.account_id}:{analysis.username}"
            for resource_access in analysis.resource_access:
                if resource_access.effect == "Deny":
                    continue
                service = resource_access.service
                if service not in ("s3", "rds"):
                    continue
                if resource_access.is_wildcard_resource:
                    targets = self._resolve_wildcard_targets(service, known_s3, known_rds)
                else:
                    targets = self._resolve_specific_targets(service, resource_access.resource_arns, known_s3, known_rds)
                for target in targets:
                    self._add_edge(GraphEdge(
                        source=source,
                        target=target,
                        type="iam_user_access_resource",
                        metadata={
                            "service": service,
                            "actions": resource_access.actions,
                            "is_wildcard_action": resource_access.is_wildcard_action,
                            "is_wildcard_resource": resource_access.is_wildcard_resource,
                            "policy_name": resource_access.policy_name,
                            "policy_arn": resource_access.policy_arn,
                            "scan_id": self.scan_id,
                            "source_type": "iam_policy_parser",
                            "created_at": self._timestamp(),
                        },
                    ))

    def _add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph.

        Duplicate edges are allowed.

        Args:
            edge: The GraphEdge to add.
        """
        self.edges.append(edge)
