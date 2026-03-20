"""
Path finding algorithms (BFS/DFS) on the constructed graph.
"""
import networkx as nx
from typing import List, Tuple

from src.facts.logger import setup_logger


class PathFinder:
    """
    Implements path finding logic to identify attack paths.
    """
    
    def __init__(self):
        self.logger = setup_logger("path_finder")
    
    def find_all_paths(
        self,
        graph: nx.DiGraph,
        entry_points: List[str],
        crown_jewels: List[str],
        max_path_length: int = 10,
    ) -> List[List[str]]:
        """
        Find all simple paths from entry points to crown jewels.
        
        Args:
            graph: NetworkX DiGraph
            entry_points: List of entry point node IDs
            crown_jewels: List of crown jewel node IDs
            max_path_length: Maximum path length
        
        Returns:
            List of paths (each path is a list of node IDs)
        """
        all_paths = []
        
        for entry in entry_points:
            for jewel in crown_jewels:
                try:
                    # Find all simple paths using NetworkX
                    paths = nx.all_simple_paths(
                        graph,
                        source=entry,
                        target=jewel,
                        cutoff=max_path_length,
                    )
                    
                    for path in paths:
                        all_paths.append(path)
                
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    # No path exists
                    continue
        
        self.logger.info(f"Found {len(all_paths)} attack paths")
        
        return all_paths
    
    def find_shortest_path(
        self, graph: nx.DiGraph, source: str, target: str
    ) -> List[str] | None:
        """
        Find shortest path between two nodes.
        
        Returns:
            Path as list of node IDs, or None if no path exists
        """
        try:
            return nx.shortest_path(graph, source=source, target=target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    
    def get_path_edges(
        self, graph: nx.DiGraph, path: List[str]
    ) -> List[Tuple[str, str, str]]:
        """
        Get edge types for a path.
        
        Returns:
            List of (source, target, edge_type) tuples
        """
        edges = []
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            if graph.has_edge(source, target):
                edge_data = graph[source][target]
                edge_type = edge_data.get("type", "unknown")
                edges.append((source, target, edge_type))
        
        return edges