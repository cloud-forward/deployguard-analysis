"""
Graph builder module - converts Facts to NetworkX graph.
"""
import networkx as nx
from typing import List, Dict, Any, Set

from src.facts.canonical_fact import Fact
from src.facts.types import NodeType
from src.facts.logger import setup_logger


class GraphBuilder:
    """
    Constructs a NetworkX graph from canonical facts.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self._created_nodes: Set[str] = set()
        self.logger = setup_logger("graph_builder")
    
    async def build_from_facts(self, facts: List[Fact]) -> nx.DiGraph:
        """
        Build a directed graph from facts.
        
        Args:
            facts: List of canonical facts
        
        Returns:
            NetworkX DiGraph
        """
        self.graph.clear()
        self._created_nodes.clear()
        
        self.logger.info(f"Building graph from {len(facts)} facts")
        
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
    
    def _add_edge(self, fact: Fact):
        """Add edge from fact"""
        self.graph.add_edge(
            fact.subject_id,
            fact.object_id,
            type=fact.fact_type,
            metadata=fact.metadata or {},
        )
    
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