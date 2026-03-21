from src.facts.id_generator import NodeIDGenerator


def test_parse_node_type_does_not_recognize_removed_node_credential_prefix():
    assert NodeIDGenerator.parse_node_type("node_cred:worker-1:token") == "node_cred"
