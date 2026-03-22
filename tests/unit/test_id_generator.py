from src.facts.id_generator import NodeIDGenerator


def test_node_credential_id_generation_uses_canonical_prefix_and_shape():
    assert NodeIDGenerator.node_credential("worker-1", "kubelet_cert") == "node_cred:worker-1:kubelet_cert"


def test_parse_node_type_recognizes_node_credential_prefix():
    assert NodeIDGenerator.parse_node_type("node_cred:worker-1:kubelet_cert") == "node_credential"
