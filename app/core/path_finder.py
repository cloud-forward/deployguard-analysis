"""
Path finding algorithms (BFS/DFS) on the constructed graph.
"""
import networkx as nx
from heapq import heappop, heappush
from typing import Iterable, Iterator, List, Tuple

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
        max_path_length: int = 7,
        max_paths: int | None = None,
    ) -> List[List[str]]:
        """
        Find bounded, deterministic attack paths from entry points to crown jewels.
        
        Args:
            graph: NetworkX DiGraph
            entry_points: List of entry point node IDs
            crown_jewels: List of crown jewel node IDs
            max_path_length: Maximum hop count
            max_paths: Maximum number of paths to return
        
        Returns:
            List of paths (each path is a list of node IDs)
        """
        if max_paths is not None and max_paths <= 0:
            return []

        ordered_entry_points = sorted(set(entry_points))
        ordered_crown_jewels = sorted(set(crown_jewels))

        queue: list[tuple[int, tuple[str, ...], int, list[str], Iterator[list[str]]]] = []
        pair_index = 0

        for entry in ordered_entry_points:
            for jewel in ordered_crown_jewels:
                iterator = self._shortest_paths_up_to_hops(
                    graph,
                    source=entry,
                    target=jewel,
                    max_path_length=max_path_length,
                )
                first_path = next(iterator, None)
                if first_path is None:
                    continue
                heappush(
                    queue,
                    (self._path_hops(first_path), tuple(first_path), pair_index, first_path, iterator),
                )
                pair_index += 1

        all_paths: list[list[str]] = []
        seen_paths: set[tuple[str, ...]] = set()

        while queue and (max_paths is None or len(all_paths) < max_paths):
            _, path_key, current_pair_index, path, iterator = heappop(queue)
            if path_key not in seen_paths:
                seen_paths.add(path_key)
                all_paths.append(path)

            next_path = next(iterator, None)
            if next_path is not None:
                heappush(
                    queue,
                    (
                        self._path_hops(next_path),
                        tuple(next_path),
                        current_pair_index,
                        next_path,
                        iterator,
                    ),
                )

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

    @staticmethod
    def _path_hops(path: List[str]) -> int:
        return max(len(path) - 1, 0)

    def _shortest_paths_up_to_hops(
        self,
        graph: nx.DiGraph,
        source: str,
        target: str,
        max_path_length: int,
    ) -> Iterator[List[str]]:
        try:
            iterator: Iterable[List[str]] = nx.shortest_simple_paths(
                graph,
                source=source,
                target=target,
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return iter(())

        def _bounded() -> Iterator[List[str]]:
            for path in iterator:
                if self._path_hops(path) > max_path_length:
                    break
                yield path

        return _bounded()
