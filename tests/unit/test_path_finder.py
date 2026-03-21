import networkx as nx

from app.core.path_finder import PathFinder


def test_find_all_paths_default_max_path_length_is_7():
    graph = nx.DiGraph()
    path = ["n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"]

    for node in path:
        graph.add_node(node)

    for source, target in zip(path, path[1:]):
        graph.add_edge(source, target)

    finder = PathFinder()

    assert finder.find_all_paths(graph, ["n0"], ["n8"]) == []
    assert finder.find_all_paths(graph, ["n0"], ["n8"], max_path_length=8) == [path]
