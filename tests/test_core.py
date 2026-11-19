from governed_mcp.core import caller, investigate_incident, search_knowledge_base, traverse_authorized_graph

def test_support_cannot_receive_confidential_dataset():
    result = traverse_authorized_graph("What does ProfileService consume?", caller("sam", ["support"], "acme", "internal", "approved"))
    assert all(fact["object"] != "CustomerDataset" for fact in result["facts"])
    assert any(event["reason"] == "relationship_denied" for event in result["audit"])

def test_analyst_can_receive_confidential_dataset_with_approved_model():
    result = traverse_authorized_graph("What does ProfileService consume?", caller("ada", ["analyst"], "acme", "confidential", "approved"))
    assert any(fact["object"] == "CustomerDataset" for fact in result["facts"])

def test_unapproved_model_never_receives_confidential_document():
    result = search_knowledge_base("customer dataset schema", caller("ada", ["analyst"], "acme", "confidential", "unapproved"))
    assert all(item["id"] != "customer-schema" for item in result["results"])

def test_investigation_returns_traceable_authorized_context():
    result = investigate_incident("ProfileService", "runbook", caller("admin", ["platform-admin"], "acme", "restricted", "approved"))
    assert result["trace_id"]
    assert result["workflow"][0] == "authorized_graph_retrieval"
