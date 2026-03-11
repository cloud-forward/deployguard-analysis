"""AWS Graph Builder base structure with core data classes."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from src.graph.builders.aws_scanner_types import AWSScanResult, EC2InstanceScan, IAMRoleScan, RDSInstanceScan, S3BucketScan, SecurityGroupScan
from src.graph.builders.cross_domain_types import IRSAMapping, SecretContainsCredentialsFact


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
    namespace: str
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

    def _add_node(self, node: GraphNode) -> None:
        """Add a node to the graph, preventing duplicates.

        If a node with the same ID already exists, it will not be added again.

        Args:
            node: The GraphNode to add.
        """
        if node.id not in self._node_ids:
            self._node_ids.add(node.id)
            self.nodes.append(node)

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
                namespace=None,
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
                namespace=None,
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
                namespace=None,
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
                namespace=None,
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

    def _build_iam_role_nodes(self, roles: list[IAMRoleScan]) -> None:
        """Build graph nodes for IAM Roles.

        Args:
            roles: List of IAMRoleScan objects to process.
        """
        # TODO: Add tier classification when IAM Policy Parser is integrated
        # tier, tier_reason, trust_analysis will be added later
        for role in roles:
            node = GraphNode(
                id=f"iam:{self.account_id}:{role.name}",
                type="iam_role",
                namespace=None,
                is_entry_point=False,
                is_crown_jewel=False,
                metadata={
                    "arn": role.arn,
                    "is_irsa": role.is_irsa,
                    "attached_policies": [
                        p["PolicyName"] for p in role.attached_policies if "PolicyName" in p
                    ],
                    "scan_id": self.scan_id,
                },
            )
            self._add_node(node)

    def _build_sg_allows_edges(self, scan: AWSScanResult) -> None:
        """Build edges from Security Groups to RDS and EC2 instances.

        Args:
            scan: The AWSScanResult containing RDS and EC2 instances.
        """
        for rds in scan.rds_instances:
            for sg_id in rds.vpc_security_groups:
                self._add_edge(GraphEdge(
                    source=f"sg:{self.account_id}:{sg_id}",
                    target=f"rds:{self.account_id}:{rds.identifier}",
                    type="security_group_allows",
                    metadata={
                        "resource_type": "rds",
                        "scan_id": self.scan_id,
                        "source_type": "aws_scanner",
                        "created_at": datetime.utcnow().isoformat() + "Z",
                    },
                ))

        for ec2 in scan.ec2_instances:
            for sg_id in ec2.security_groups:
                self._add_edge(GraphEdge(
                    source=f"sg:{self.account_id}:{sg_id}",
                    target=f"ec2:{self.account_id}:{ec2.instance_id}",
                    type="security_group_allows",
                    metadata={
                        "resource_type": "ec2",
                        "scan_id": self.scan_id,
                        "source_type": "aws_scanner",
                        "created_at": datetime.utcnow().isoformat() + "Z",
                    },
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
                    "via": "instance_profile",
                    "scan_id": self.scan_id,
                    "source_type": "aws_scanner",
                    "created_at": datetime.utcnow().isoformat() + "Z",
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
                    "annotation": mapping.iam_role_arn,
                    "role_arn": mapping.iam_role_arn,
                    "via": "irsa",
                    "scan_id": self.scan_id,
                    "source_type": "aws_scanner",
                    "created_at": datetime.utcnow().isoformat() + "Z",
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
            self._add_edge(GraphEdge(
                source=f"secret:{fact.secret_namespace}:{fact.secret_name}",
                target=f"{fact.target_type}:{self.account_id}:{fact.target_id}",
                type="secret_contains_credentials",
                metadata={
                    "matched_keys": fact.matched_keys,
                    "confidence": fact.confidence,
                    "scan_id": self.scan_id,
                    "source_type": "aws_scanner",
                    "created_at": datetime.utcnow().isoformat() + "Z",
                },
            ))

    def build(
        self,
        scan: AWSScanResult,
        irsa_mappings: list[IRSAMapping],
        credential_facts: list[SecretContainsCredentialsFact],
        policy_results: Optional[list["IAMPolicyAnalysisResult"]] = None,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """
        Build AWS graph nodes and edges from scan data.

        Args:
            scan: AWS Scanner output containing all resource data
            irsa_mappings: Service Account to IAM Role mappings from K8s Scanner
            credential_facts: Secret to AWS resource credential mappings
            policy_results: IAM Policy analysis results (Phase 3, currently not used)

        Returns:
            Tuple of (nodes, edges)

        Phase 1 Implementation:
            - Creates nodes: IAM Role, S3, RDS, SecurityGroup, EC2
            - Creates edges: SG allows, Instance Profile, IRSA, Credentials

        Phase 3 TODO:
            - Implement _build_iam_access_edges() when policy_results is provided
            - Update _build_iam_role_nodes() to use policy analysis for tier classification
        """
        # Nodes first
        self._build_iam_role_nodes(scan.iam_roles)
        self._build_s3_nodes(scan.s3_buckets)
        self._build_rds_nodes(scan.rds_instances)
        self._build_security_group_nodes(scan.security_groups)
        self._build_ec2_nodes(scan.ec2_instances)

        # Then edges
        if policy_results is not None:
            # TODO: Implement in Phase 3 when IAM Policy Parser is integrated
            # self._build_iam_access_edges(policy_results, scan)
            pass

        self._build_sg_allows_edges(scan)
        self._build_instance_profile_edges(scan.ec2_instances)
        self._build_irsa_edges(irsa_mappings)
        self._build_credential_edges(credential_facts)

        return (self.nodes, self.edges)

    def _add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph.

        Duplicate edges are allowed.

        Args:
            edge: The GraphEdge to add.
        """
        self.edges.append(edge)
