"""
Risk scoring module for attack paths.
"""
import networkx as nx
from typing import List, Dict, Any

from src.facts.logger import setup_logger


class RiskEngine:
    """
    Evaluates risks based on identified paths and node vulnerabilities.
    """
    
    def __init__(self):
        self.logger = setup_logger("risk_engine")
    
    def calculate_path_risk(
        self, graph: nx.DiGraph, path: List[str]
    ) -> float:
        """
        Calculate risk score for a path.
        
        Args:
            graph: NetworkX DiGraph
            path: List of node IDs in path
        
        Returns:
            Risk score (0.0 - 1.0)
        """
        if not path:
            return 0.0
        
        # Aggregate base_risk from all nodes in path
        risk_scores = []
        
        for node_id in path:
            if node_id in graph:
                base_risk = graph.nodes[node_id].get("base_risk", 0.0)
                risk_scores.append(base_risk)
        
        if not risk_scores:
            return 0.0
        
        # Use max risk in path
        path_risk = max(risk_scores)
        
        # Apply path length penalty (longer paths = slightly lower risk)
        length_factor = 1.0 - (len(path) * 0.02)
        length_factor = max(length_factor, 0.7)  # Floor at 0.7
        
        final_risk = path_risk * length_factor
        
        return min(final_risk, 1.0)
    
    def calculate_node_risk(
        self, graph: nx.DiGraph, node_id: str
    ) -> Dict[str, Any]:
        """
        Calculate detailed risk for a single node.
        
        Returns:
            Dict with risk score and factors
        """
        if node_id not in graph:
            return {"score": 0.0, "factors": []}
        
        attrs = graph.nodes[node_id]
        base_risk = attrs.get("base_risk", 0.0)
        
        factors = []
        
        if attrs.get("is_entry_point"):
            factors.append("Entry Point")
        
        if attrs.get("is_crown_jewel"):
            factors.append("Crown Jewel")
        
        node_type = attrs.get("type", "")
        metadata = attrs.get("metadata", {})
        
        # Type-specific factors
        if node_type == "pod":
            if metadata.get("is_privileged"):
                factors.append("Privileged Container")
        
        elif node_type in ("role", "cluster_role"):
            if metadata.get("has_wildcard_verb"):
                factors.append("Wildcard Permissions")
            if metadata.get("has_pod_exec"):
                factors.append("Pod Exec Permission")
        
        elif node_type == "iam_role":
            tier = metadata.get("tier")
            if tier == 1:
                factors.append("Admin IAM Role")
            elif tier == 2:
                factors.append("Privilege Escalation Risk")
        
        return {
            "score": base_risk,
            "factors": factors,
        }