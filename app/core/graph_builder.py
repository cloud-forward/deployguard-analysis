"""NetworkX graph adapter for unified and legacy graph inputs."""
import networkx as nx
from typing import List, Dict, Any, Set

from src.facts.canonical_fact import Fact
from src.facts.id_generator import NodeIDGenerator
from src.facts.types import NodeType
from src.facts.logger import setup_logger
from src.facts.validation.rules import ValidationRules
from src.graph.builders.build_result_types import (
    UnifiedGraphResult,
    graph_edge_attrs,
    graph_node_attrs,
)

PREFIX_TO_NODE_TYPE = {
    prefix.rstrip(":"): node_type
    for node_type, prefix in ValidationRules.TYPE_PREFIX_MAP.items()
}


class GraphBuilder:
    """Adapts unified graph results to NetworkX, with facts as fallback only."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self._created_nodes: Set[str] = set()
        self.logger = setup_logger("graph_builder")
    
    async def build_from_facts(self, facts: List[Fact]) -> nx.DiGraph:
        """
        Transitional fallback: build a directed graph from canonical facts.
        
        Args:
            facts: List of canonical facts
        
        Returns:
            NetworkX DiGraph
        """
        self._reset_graph()
        
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
        
        return self._finalize_graph()

    async def build_from_unified_result(
        self,
        unified_result: UnifiedGraphResult,
    ) -> nx.DiGraph:
        """Primary path: translate a UnifiedGraphResult into NetworkX.

        This adapter only:
        - copies unified nodes into NetworkX node attributes
        - copies unified edges into NetworkX edge attributes
        - creates explicit placeholder nodes for dangling edge endpoints so
          downstream NetworkX consumers still see a consistent graph shape

        It does not discover new relationships or rebuild domain graphs.
        """
        self._reset_graph()

        self.logger.info(
            f"Building graph from unified result: {len(unified_result.nodes)} nodes, "
            f"{len(unified_result.edges)} edges"
        )

        for node in unified_result.nodes:
            self._add_unified_node(node)

        for edge in unified_result.edges:
            self._add_unified_edge(edge)

        return self._finalize_graph()
    
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

    def _add_unified_node(self, node) -> None:
        """Copy a typed unified node into the NetworkX graph."""
        node_attrs = graph_node_attrs(node)
        self.graph.add_node(node.id, **node_attrs)
        self._created_nodes.add(node.id)

    def _add_unified_edge(self, edge) -> None:
        """Copy a typed unified edge into the NetworkX graph."""
        self._ensure_unified_endpoint_node(edge.source)
        self._ensure_unified_endpoint_node(edge.target)
        edge_attrs = graph_edge_attrs(edge)
        self._add_edge_by_values(
            source=edge_attrs["source"],
            target=edge_attrs["target"],
            edge_type=edge_attrs["type"],
            metadata=edge_attrs["metadata"],
        )

    def _ensure_unified_endpoint_node(self, node_id: str) -> None:
        """Add a placeholder node only when a unified edge references a missing endpoint."""
        if node_id in self._created_nodes:
            return

        node_type = self._canonical_placeholder_node_type(node_id)
        self.graph.add_node(
            node_id,
            id=node_id,
            type=node_type,
            is_entry_point=False,
            is_crown_jewel=False,
            base_risk=0.0,
            metadata={"adapter_placeholder": True},
        )
        self._created_nodes.add(node_id)

    def _canonical_placeholder_node_type(self, node_id: str) -> str:
        parsed_type = NodeIDGenerator.parse_node_type(node_id)
        if not parsed_type:
            return "unknown"
        return PREFIX_TO_NODE_TYPE.get(parsed_type, parsed_type)
    
    def _add_edge(self, fact: Fact):
        """Add edge from fact"""
        self._add_edge_by_values(
            source=fact.subject_id,
            target=fact.object_id,
            edge_type=fact.fact_type,
            metadata=fact.metadata or {},
        )

    def _add_edge_by_values(
        self,
        source: str,
        target: str,
        edge_type: str,
        metadata: Dict[str, Any],
    ) -> None:
        self.graph.add_edge(
            source,
            target,
            type=edge_type,
            metadata=metadata,
        )

    def _reset_graph(self) -> None:
        self.graph.clear()
        self._created_nodes.clear()

    def _finalize_graph(self) -> nx.DiGraph:
        self._mark_entry_points()
        self._mark_crown_jewels()
        self._update_base_risk()
        return self.graph
    
    # ========================================
    # Node Classification
    # ========================================
    
    def _mark_entry_points(self):
        """Mark entry point nodes"""
        for node_id, attrs in self.graph.nodes(data=True):
            self.graph.nodes[node_id]["is_entry_point"] = self._classify_entry_point(
                node_id,
                attrs,
            )
    
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
            self.graph.nodes[node_id]["is_crown_jewel"] = self._classify_crown_jewel(attrs)

    def _classify_entry_point(self, node_id: str, attrs: Dict[str, Any]) -> bool:
        """Return whether this node should be treated as an attack-path entry point."""
        node_type = attrs.get("type")
        metadata = attrs.get("metadata", {})

        if node_type == NodeType.INGRESS.value:
            return True

        if node_type == NodeType.SERVICE.value:
            return self._is_service_exposed_by_ingress(node_id)

        if node_type == NodeType.POD.value:
            return self._is_pod_exposed_by_ingress(node_id)

        if node_type == NodeType.RDS.value:
            return bool(metadata.get("is_publicly_accessible"))

        if node_type == NodeType.S3_BUCKET.value:
            return bool(metadata.get("is_public"))

        return False

    def _classify_crown_jewel(self, attrs: Dict[str, Any]) -> bool:
        """Return whether this node should be treated as an attack-path crown jewel."""
        node_type = attrs.get("type")
        metadata = attrs.get("metadata", {})

        if node_type in (NodeType.S3_BUCKET.value, NodeType.RDS.value):
            return True

        if node_type == NodeType.SECRET.value:
            return bool(
                metadata.get("contains_db_credentials")
                or metadata.get("contains_aws_credentials")
            )

        if node_type in (NodeType.IAM_ROLE.value, NodeType.IAM_USER.value):
            return metadata.get("tier") in (1, 2)

        return False

    def _is_service_exposed_by_ingress(self, service_id: str) -> bool:
        """Check if a service is directly exposed by an ingress-like entry point."""
        for pred in self.graph.predecessors(service_id):
            if self.graph.nodes[pred].get("type") == NodeType.INGRESS.value:
                return True
        return False

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
        return sorted([
            node_id
            for node_id, attrs in self.graph.nodes(data=True)
            if attrs.get("is_entry_point", False)
        ])
    
    def get_crown_jewels(self) -> List[str]:
        """Get all crown jewel node IDs"""
        return sorted([
            node_id
            for node_id, attrs in self.graph.nodes(data=True)
            if attrs.get("is_crown_jewel", False)
        ])
    
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
