"""
Graph builder module - converts Facts to NetworkX graph.
"""
import networkx as nx
from typing import List, Dict, Any, Set

from src.facts.canonical_fact import Fact
from src.facts.types import NodeType
from src.facts.logger import setup_logger
from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    EC2InstanceScan,
    IAMRoleScan,
    IAMUserScan,
    RDSInstanceScan,
    S3BucketScan,
    SecurityGroupScan,
)
from src.graph.builders.iam_policy_types import (
    IAMPolicyAnalysisResult,
    IAMUserPolicyAnalysisResult,
)
from src.graph.builders.k8s_graph_builder import K8sGraphBuilder
from src.graph.graph_models import GraphNode, GraphEdge


class GraphBuilder:
    """
    Constructs a NetworkX graph from canonical facts.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self._created_nodes: Set[str] = set()
        self._seeded_edge_keys: Set[tuple[str, str, str]] = set()
        self.logger = setup_logger("graph_builder")
        self._k8s_builder = K8sGraphBuilder()
    
    async def build_from_facts(
        self,
        facts: List[Fact],
        k8s_scan: Dict[str, Any] | None = None,
        scan_id: str | None = None,
        aws_scan: Dict[str, Any] | None = None,
        policy_results: List[IAMPolicyAnalysisResult] | None = None,
        user_policy_results: List[IAMUserPolicyAnalysisResult] | None = None,
    ) -> nx.DiGraph:
        """
        Build a directed graph from facts.
        
        Args:
            facts: List of canonical facts
            k8s_scan: Raw Kubernetes scan data used for K8s node enrichment
            scan_id: Scan ID associated with the Kubernetes scan
            aws_scan: Raw AWS scan data used for AWS node enrichment
            policy_results: Optional IAM role policy analysis for AWS typed edges
            user_policy_results: Optional IAM user policy analysis for AWS typed edges
        
        Returns:
            NetworkX DiGraph
        """
        self.graph.clear()
        self._created_nodes.clear()
        self._seeded_edge_keys.clear()
        
        self.logger.info(f"Building graph from {len(facts)} facts")

        if k8s_scan is not None:
            effective_scan_id = scan_id or k8s_scan.get("scan_id", "unknown")
            k8s_nodes, k8s_edges = self._k8s_builder.build(
                facts=facts,
                k8s_scan=k8s_scan,
                scan_id=effective_scan_id,
            )
            self._seed_prebuilt_graph(k8s_nodes, k8s_edges)

        if aws_scan is not None:
            aws_result = self._to_aws_scan_result(aws_scan)
            if aws_result is not None:
                aws_builder = AWSGraphBuilder(
                    account_id=aws_result.aws_account_id,
                    scan_id=aws_result.scan_id,
                )
                aws_nodes, aws_edges = aws_builder.build(
                    aws_result,
                    irsa_mappings=[],
                    credential_facts=[],
                    policy_results=policy_results,
                    user_policy_results=user_policy_results,
                )
                self._seed_prebuilt_graph(aws_nodes, aws_edges)
        
        # Step 1: Create nodes and edges from facts
        for fact in facts:
            self._ensure_node(fact.subject_id, fact.subject_type)
            self._ensure_node(fact.object_id, fact.object_type)
            self._add_edge(fact)
        
        self.logger.info(
            f"Graph created: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )
        
        # Step 2: Classify nodes
        self._mark_entry_points()
        self._mark_crown_jewels()
        self._update_base_risk()
        
        return self.graph

    def _seed_prebuilt_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge],
    ) -> None:
        """Seed graph state from typed builder output before fact fallback."""
        for node in nodes:
            self._add_prebuilt_node(node)
        for edge in edges:
            self._seeded_edge_keys.add((edge.source, edge.target, edge.type))
            self.graph.add_edge(
                edge.source,
                edge.target,
                type=edge.type,
                metadata=edge.metadata or {},
            )
    
    def _ensure_node(self, node_id: str, node_type: str):
        """Create node if it doesn't exist"""
        if node_id in self._created_nodes:
            return
        
        self.graph.add_node(
            node_id,
            id=node_id,
            type=node_type,
            is_entry_point=False,
            is_crown_jewel=False,
            base_risk=0.0,
            metadata={},
        )
        self._created_nodes.add(node_id)

    def _node_attr(self, node: Any, name: str, default: Any) -> Any:
        """Safely read fields from typed builder node objects with minor shape differences."""
        return getattr(node, name, default)

    def _add_prebuilt_node(self, node: GraphNode):
        """Create a node from builder output if it doesn't exist yet."""
        node_id = self._node_attr(node, "id", None)
        if not node_id:
            return
        if node_id in self._created_nodes:
            return

        base_risk = self._node_attr(node, "base_risk", 0.0)
        self.graph.add_node(
            node_id,
            id=node_id,
            type=self._node_attr(node, "type", "unknown"),
            is_entry_point=self._node_attr(node, "is_entry_point", False),
            is_crown_jewel=self._node_attr(node, "is_crown_jewel", False),
            base_risk=base_risk,
            metadata=self._node_attr(node, "metadata", {}) or {},
        )
        self._created_nodes.add(node_id)
    
    def _add_edge(self, fact: Fact):
        """Add edge from fact"""
        if self._is_seeded_internal_edge(fact):
            return
        self.graph.add_edge(
            fact.subject_id,
            fact.object_id,
            type=fact.fact_type,
            metadata=fact.metadata or {},
        )

    def _is_seeded_internal_edge(self, fact: Fact) -> bool:
        """Skip re-adding internal edges already seeded from typed builders."""
        edge_key = (fact.subject_id, fact.object_id, fact.fact_type)
        return edge_key in self._seeded_edge_keys

    def _to_aws_scan_result(self, aws_scan: Dict[str, Any]) -> AWSScanResult | None:
        """Convert a raw AWS scan dict into the typed result needed by AWSGraphBuilder."""
        account_id = aws_scan.get("aws_account_id")
        scan_id = aws_scan.get("scan_id")
        scanned_at = aws_scan.get("scanned_at")

        if not isinstance(account_id, str) or not account_id:
            return None
        if not isinstance(scan_id, str) or not scan_id:
            return None
        if not isinstance(scanned_at, str) or not scanned_at:
            scanned_at = scan_id

        return AWSScanResult(
            scan_id=scan_id,
            aws_account_id=account_id,
            scanned_at=scanned_at,
            iam_roles=self._typed_aws_list(aws_scan.get("iam_roles"), IAMRoleScan),
            s3_buckets=self._typed_aws_list(aws_scan.get("s3_buckets"), S3BucketScan),
            rds_instances=self._typed_aws_list(aws_scan.get("rds_instances"), RDSInstanceScan),
            ec2_instances=self._typed_aws_list(aws_scan.get("ec2_instances"), EC2InstanceScan),
            security_groups=self._typed_aws_list(aws_scan.get("security_groups"), SecurityGroupScan),
            iam_users=self._typed_aws_list(aws_scan.get("iam_users"), IAMUserScan),
            region=aws_scan.get("region"),
        )

    def _typed_aws_list(self, items: Any, cls):
        if not isinstance(items, list):
            return []

        typed_items = []
        for item in items:
            if isinstance(item, cls):
                typed_items.append(item)
            elif isinstance(item, dict):
                try:
                    typed_items.append(cls(**item))
                except TypeError:
                    continue
        return typed_items
    
    # ========================================
    # Node Classification
    # ========================================
    
    def _mark_entry_points(self):
        """Mark entry point nodes"""
        for node_id, attrs in self.graph.nodes(data=True):
            node_type = attrs.get("type")
            
            # Rule 1: Ingress is always entry point
            if node_type == NodeType.INGRESS.value:
                self.graph.nodes[node_id]["is_entry_point"] = True
            
            # Rule 2: Pods exposed by Ingress
            elif node_type == NodeType.POD.value:
                # Check if any Ingress → Service → Pod path exists
                if self._is_pod_exposed_by_ingress(node_id):
                    self.graph.nodes[node_id]["is_entry_point"] = True
            
            # Rule 3: Public RDS (if metadata indicates)
            elif node_type == NodeType.RDS.value:
                if attrs.get("metadata", {}).get("is_publicly_accessible"):
                    self.graph.nodes[node_id]["is_entry_point"] = True
            
            # Rule 4: Public S3 (if metadata indicates)
            elif node_type == NodeType.S3_BUCKET.value:
                if attrs.get("metadata", {}).get("is_public"):
                    self.graph.nodes[node_id]["is_entry_point"] = True
    
    def _is_pod_exposed_by_ingress(self, pod_id: str) -> bool:
        """Check if pod is exposed by Ingress → Service → Pod path"""
        # Find services targeting this pod
        services = []
        for pred in self.graph.predecessors(pod_id):
            if self.graph.nodes[pred].get("type") == NodeType.SERVICE.value:
                services.append(pred)
        
        # Check if any service is exposed by Ingress
        for service_id in services:
            for pred in self.graph.predecessors(service_id):
                if self.graph.nodes[pred].get("type") == NodeType.INGRESS.value:
                    return True
        
        return False
    
    def _mark_crown_jewels(self):
        """Mark crown jewel nodes"""
        for node_id, attrs in self.graph.nodes(data=True):
            node_type = attrs.get("type")
            metadata = attrs.get("metadata", {})
            
            is_cj = False
            
            # Rule 1: S3 buckets are always crown jewels
            if node_type == NodeType.S3_BUCKET.value:
                is_cj = True
            
            # Rule 2: RDS instances are always crown jewels
            elif node_type == NodeType.RDS.value:
                is_cj = True
            
            # Rule 3: Secrets with credentials
            elif node_type == NodeType.SECRET.value:
                if (
                    metadata.get("contains_db_credentials")
                    or metadata.get("contains_aws_credentials")
                ):
                    is_cj = True
            
            # Rule 4: IAM Roles (Tier 1 or 2)
            elif node_type == NodeType.IAM_ROLE.value:
                tier = metadata.get("tier")
                if tier in (1, 2):
                    is_cj = True
            
            # Rule 5: IAM Users (Tier 1 or 2)
            elif node_type == NodeType.IAM_USER.value:
                tier = metadata.get("tier")
                if tier in (1, 2):
                    is_cj = True
            
            if is_cj:
                self.graph.nodes[node_id]["is_crown_jewel"] = True
    
    def _update_base_risk(self):
        """Update base_risk for all nodes"""
        for node_id, attrs in self.graph.nodes(data=True):
            node_type = attrs.get("type")
            metadata = attrs.get("metadata", {})
            is_crown_jewel = attrs.get("is_crown_jewel", False)
            
            base_risk = self._calculate_base_risk(node_type, metadata, is_crown_jewel)
            self.graph.nodes[node_id]["base_risk"] = base_risk
    
    def _calculate_base_risk(
        self, node_type: str, metadata: Dict[str, Any], is_crown_jewel: bool
    ) -> float:
        """Calculate base risk for a node"""
        
        if node_type == NodeType.POD.value:
            base = 0.3
            if metadata.get("is_privileged"):
                base = 0.6
            return base
        
        elif node_type == NodeType.SERVICE_ACCOUNT.value:
            base = 0.2
            if metadata.get("has_irsa_annotation"):
                base = 0.4
            return base
        
        elif node_type in (NodeType.ROLE.value, NodeType.CLUSTER_ROLE.value):
            base = 0.2
            if metadata.get("has_wildcard_verb"):
                base = 0.7
            elif metadata.get("has_pod_exec"):
                base = 0.6
            return base
        
        elif node_type == NodeType.SECRET.value:
            base = 0.3
            if is_crown_jewel:
                base = 0.7
            return base
        
        elif node_type == NodeType.SERVICE.value:
            return 0.1
        
        elif node_type == NodeType.INGRESS.value:
            return 0.4
        
        elif node_type == NodeType.NODE.value:
            return 0.5
        
        elif node_type == NodeType.NODE_CREDENTIAL.value:
            base = 0.8
            if metadata.get("grants_cluster_admin"):
                base = 0.95
            return base
        
        elif node_type == NodeType.CONTAINER_IMAGE.value:
            base = 0.2
            critical_cve = metadata.get("critical_cve_count", 0)
            high_cve = metadata.get("high_cve_count", 0)
            if critical_cve > 0:
                base = 0.7
            elif high_cve > 5:
                base = 0.5
            return base
        
        elif node_type == NodeType.IAM_ROLE.value:
            tier = metadata.get("tier")
            tier_map = {1: 0.9, 2: 0.7, 3: 0.5}
            return tier_map.get(tier, 0.3)
        
        elif node_type == NodeType.IAM_USER.value:
            tier = metadata.get("tier")
            base = {1: 0.9, 2: 0.7, 3: 0.5}.get(tier, 0.3)
            if not metadata.get("has_mfa", True):
                base = min(base + 0.1, 1.0)
            return base
        
        elif node_type == NodeType.S3_BUCKET.value:
            if metadata.get("is_public"):
                return 0.9
            return 0.5
        
        elif node_type == NodeType.RDS.value:
            if metadata.get("is_publicly_accessible"):
                return 0.95
            return 0.6
        
        elif node_type == NodeType.SECURITY_GROUP.value:
            if metadata.get("has_open_ingress"):
                return 0.7
            return 0.3
        
        elif node_type == NodeType.EC2_INSTANCE.value:
            base = 0.3
            if metadata.get("has_instance_profile"):
                base = 0.5
            if metadata.get("is_k8s_worker"):
                base += 0.1
            return base
        
        return 0.3  # Default
    
    # ========================================
    # Query Methods
    # ========================================
    
    def get_entry_points(self) -> List[str]:
        """Get all entry point node IDs"""
        return [
            node_id
            for node_id, attrs in self.graph.nodes(data=True)
            if attrs.get("is_entry_point", False)
        ]
    
    def get_crown_jewels(self) -> List[str]:
        """Get all crown jewel node IDs"""
        return [
            node_id
            for node_id, attrs in self.graph.nodes(data=True)
            if attrs.get("is_crown_jewel", False)
        ]
    
    def get_node_attributes(self, node_id: str) -> Dict[str, Any]:
        """Get attributes of a node"""
        if node_id not in self.graph:
            return {}
        return dict(self.graph.nodes[node_id])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary for serialization"""
        return {
            "nodes": [
                {"id": node_id, **attrs}
                for node_id, attrs in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **attrs}
                for u, v, attrs in self.graph.edges(data=True)
            ],
        }
