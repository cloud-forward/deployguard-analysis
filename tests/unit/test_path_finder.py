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


def test_find_all_paths_returns_deterministic_shortest_first_paths_with_explicit_top_k():
    graph = nx.DiGraph()
    edges = [
        ("entry", "a"),
        ("a", "target"),
        ("entry", "b"),
        ("b", "target"),
        ("entry", "c"),
        ("c", "d"),
        ("d", "target"),
    ]
    for source, target in edges:
        graph.add_edge(source, target)

    finder = PathFinder()

    assert finder.find_all_paths(
        graph,
        ["entry"],
        ["target"],
        max_path_length=3,
        max_paths=2,
    ) == [
        ["entry", "a", "target"],
        ["entry", "b", "target"],
    ]


def test_find_all_paths_respects_zero_top_k():
    graph = nx.DiGraph()
    graph.add_edge("entry", "target")

    assert PathFinder().find_all_paths(
        graph,
        ["entry"],
        ["target"],
        max_paths=0,
    ) == []
