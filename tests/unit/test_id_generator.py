from src.facts.id_generator import NodeIDGenerator


def test_parse_node_type_recognizes_service_account_prefix():
    assert NodeIDGenerator.parse_node_type("sa:production:api-sa") == "service_account"


def test_parse_node_type_returns_raw_prefix_for_unknown_ids():
    assert NodeIDGenerator.parse_node_type("node_cred:worker-1:kubelet_cert") == "node_cred"
